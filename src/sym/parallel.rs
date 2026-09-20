//! Bounded, ordered payload workers. I/O and progress callbacks stay on the caller.
use std::{cell::Cell, sync::mpsc, thread};

use crate::error::{AppError, Result};

thread_local! {
    static THREADS: Cell<usize> = const { Cell::new(0) };
}

/// Run synchronous encryption/decryption with a payload worker limit.
/// Zero selects available parallelism; one disables workers. The setting is
/// local to the calling thread and restored even during unwinding.
pub fn with_threads<T>(threads: usize, operation: impl FnOnce() -> T) -> T {
    struct Restore(usize);
    impl Drop for Restore {
        fn drop(&mut self) {
            THREADS.with(|value| value.set(self.0));
        }
    }
    let _restore = Restore(THREADS.with(|value| value.replace(threads)));
    operation()
}

/// Budget includes both input and output buffers, including completed results.
/// It excludes the existing I/O buffers and Argon2 allocation.
pub(crate) fn workers(chunk_bytes: usize, chunks: u64) -> usize {
    const BUDGET: usize = 64 * 1024 * 1024;
    let requested = THREADS.with(Cell::get);
    let requested = if requested == 0 {
        thread::available_parallelism().map_or(1, usize::from)
    } else {
        requested
    };
    requested
        .min(32)
        .min((BUDGET / chunk_bytes.saturating_mul(2).max(1)).max(1))
        .min(usize::try_from(chunks).unwrap_or(usize::MAX))
        .max(1)
}

fn worker_error() -> AppError {
    AppError::CryptoConfig("Payload worker terminated unexpectedly".into())
}

/// Process at most one batch of N chunks at once with N persistent workers.
/// Each channel has capacity one; outputs are consumed in submission order.
pub(crate) fn ordered<T: Send, U: Send>(
    count: u64,
    workers: usize,
    mut read: impl FnMut(u64) -> Result<T>,
    transform: impl Fn(u64, T) -> Result<U> + Sync,
    mut write: impl FnMut(U) -> Result<()>,
) -> Result<()> {
    thread::scope(|scope| {
        let mut channels = Vec::new();
        let mut handles = Vec::new();
        let result = (|| {
            for _ in 0..workers {
                let (send, receive) = mpsc::sync_channel::<(u64, T)>(1);
                let (output, results) = mpsc::sync_channel(1);
                let transform = &transform;
                handles.push(thread::Builder::new().spawn_scoped(scope, move || {
                    while let Ok((index, input)) = receive.recv() {
                        if output.send(transform(index, input)).is_err() {
                            break;
                        }
                    }
                })?);
                channels.push((send, results));
            }
            let mut index = 0;
            while index < count {
                let batch = (count - index).min(workers as u64) as usize;
                for (offset, (send, _)) in channels.iter().take(batch).enumerate() {
                    let index = index + offset as u64;
                    send.send((index, read(index)?))
                        .map_err(|_| worker_error())?;
                }
                for (_, results) in channels.iter().take(batch) {
                    write(results.recv().map_err(|_| worker_error())??)?;
                }
                index += batch as u64;
            }
            Ok(())
        })();
        // Drop both ends before joining: errors cannot leave blocked workers.
        drop(channels);
        let mut panicked = false;
        for handle in handles {
            panicked |= handle.join().is_err();
        }
        if panicked {
            Err(worker_error())
        } else {
            result
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn workers_execute_concurrently_but_write_in_order() {
        let barrier = Barrier::new(4);
        let mut output = Vec::new();
        ordered(
            8,
            4,
            Ok,
            |_, input| {
                barrier.wait();
                Ok(input)
            },
            |value| {
                output.push(value);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(output, (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn worker_and_io_failures_join_without_deadlock() {
        for failure in 0..3 {
            let result = ordered(
                8,
                4,
                |index| {
                    if failure == 0 && index == 2 {
                        Err(worker_error())
                    } else {
                        Ok(index)
                    }
                },
                |index, value| {
                    if failure == 1 && index == 1 {
                        Err(worker_error())
                    } else {
                        Ok(value)
                    }
                },
                |_| {
                    if failure == 2 {
                        Err(worker_error())
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
        }
        assert!(ordered(
            4,
            4,
            Ok,
            |_, _: u64| -> Result<()> {
                panic!("test worker panic");
            },
            |_| Ok(())
        )
        .is_err());
    }

    #[test]
    fn worker_limit_obeys_memory_and_restores_nested_settings() {
        with_threads(4, || {
            assert_eq!(workers(1024, 20), 4);
            with_threads(1, || assert_eq!(workers(1024, 20), 1));
            assert_eq!(workers(1024, 20), 4);
            assert_eq!(workers(32 * 1024 * 1024, 20), 1);
            assert_eq!(workers(1024, 1), 1);
        });
    }
}
