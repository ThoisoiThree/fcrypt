//! Staged output files that are removed when the process is interrupted.
//!
//! `NamedTempFile` deletes itself on drop, but destructors do not run when a
//! signal terminates the process. Every staged output is registered here, and
//! the termination handler removes all registered paths before exiting.
//! Recovery backups created during rollback are intentionally not tracked:
//! deleting them mid-transaction could lose the only copy of a replaced file.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use tempfile::NamedTempFile;

/// Exit status used after SIGINT, SIGTERM, SIGHUP, or Ctrl-C.
pub const INTERRUPTED_EXIT_CODE: i32 = 130;

static PENDING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn pending() -> MutexGuard<'static, Vec<PathBuf>> {
    PENDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Install a handler that removes staged outputs and exits on termination
/// signals. Call once from the binary before any output is staged.
pub fn install_interrupt_handler() -> io::Result<()> {
    ctrlc::set_handler(|| {
        remove_pending_files();
        eprintln!("Interrupted. Incomplete output files were removed.");
        std::process::exit(INTERRUPTED_EXIT_CODE);
    })
    .map_err(io::Error::other)
}

/// Remove every registered staged file. The registry lock is held until the
/// process exits, so no staged file can be published concurrently.
fn remove_pending_files() {
    let paths = pending();
    for path in paths.iter() {
        let _ = fs::remove_file(path);
    }
    // Keep the lock: publishing threads block instead of racing process exit.
    std::mem::forget(paths);
}

/// A `NamedTempFile` whose path is removed if the process is interrupted.
pub struct TrackedTempFile {
    file: Option<NamedTempFile>,
    path: PathBuf,
}

impl TrackedTempFile {
    /// Create and register a temporary file in `dir`. Registration happens
    /// under the registry lock, so an interrupt cannot miss the new file.
    pub fn new_in(dir: &Path) -> io::Result<Self> {
        let mut paths = pending();
        let file = NamedTempFile::new_in(dir)?;
        let path = file.path().to_path_buf();
        paths.push(path.clone());
        Ok(Self {
            file: Some(file),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn as_file(&self) -> &fs::File {
        self.inner().as_file()
    }

    pub fn as_file_mut(&mut self) -> &mut fs::File {
        self.file
            .as_mut()
            .expect("tracked temporary file is present until consumed")
            .as_file_mut()
    }

    /// Atomically publish the file at `destination`. On failure the staged
    /// file is removed before the error is returned.
    pub fn persist(mut self, destination: &Path, allow_overwrite: bool) -> io::Result<()> {
        let file = self
            .file
            .take()
            .expect("tracked temporary file is present until consumed");
        // Hold the lock across the rename so an interrupt either removes the
        // staged file first or observes it already published.
        let _paths = pending();
        let result = if allow_overwrite {
            file.persist(destination)
        } else {
            file.persist_noclobber(destination)
        };
        result.map(|_| ()).map_err(|error| error.error)
    }

    fn inner(&self) -> &NamedTempFile {
        self.file
            .as_ref()
            .expect("tracked temporary file is present until consumed")
    }
}

impl Drop for TrackedTempFile {
    fn drop(&mut self) {
        // Delete first, then unregister, so there is no untracked window.
        drop(self.file.take());
        let mut paths = pending();
        if let Some(index) = paths.iter().position(|path| *path == self.path) {
            paths.swap_remove(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn is_registered(path: &Path) -> bool {
        pending().iter().any(|pending| pending == path)
    }

    #[test]
    fn staged_file_is_registered_until_published() {
        let dir = tempdir().expect("tempdir must be created");
        let output = dir.path().join("output.bin");
        let mut staged = TrackedTempFile::new_in(dir.path()).expect("temp must be created");
        let staged_path = staged.path().to_path_buf();
        staged.as_file_mut().write_all(b"data").unwrap();
        assert!(is_registered(&staged_path));

        staged
            .persist(&output, false)
            .expect("persist must succeed");

        assert!(!is_registered(&staged_path));
        assert_eq!(fs::read(output).unwrap(), b"data");
    }

    #[test]
    fn dropped_or_failed_staged_file_is_removed_and_unregistered() {
        let dir = tempdir().expect("tempdir must be created");
        let dropped = TrackedTempFile::new_in(dir.path()).expect("temp must be created");
        let dropped_path = dropped.path().to_path_buf();
        drop(dropped);
        assert!(!dropped_path.exists());
        assert!(!is_registered(&dropped_path));

        let existing = dir.path().join("existing.bin");
        fs::write(&existing, b"old").unwrap();
        let failed = TrackedTempFile::new_in(dir.path()).expect("temp must be created");
        let failed_path = failed.path().to_path_buf();
        let error = failed
            .persist(&existing, false)
            .expect_err("noclobber persist must fail");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(!failed_path.exists());
        assert!(!is_registered(&failed_path));
        assert_eq!(fs::read(existing).unwrap(), b"old");
    }
}
