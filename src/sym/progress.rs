use indicatif::{ProgressBar, ProgressStyle};
use std::cell::Cell;
use std::io::IsTerminal;

pub struct OperationProgress {
    progress: ProgressBar,
    total: u64,
    message: String,
    started_payload: Cell<bool>,
}

pub fn create_progress(total: u64, message: &str, enabled: bool) -> OperationProgress {
    if !enabled || !std::io::stderr().is_terminal() {
        return OperationProgress {
            progress: ProgressBar::hidden(),
            total,
            message: message.to_owned(),
            started_payload: Cell::new(true),
        };
    }
    let progress = ProgressBar::new_spinner();
    progress.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .expect("spinner template must be valid"),
    );
    progress.set_message(format!("{message}: preparing keys"));
    progress.enable_steady_tick(std::time::Duration::from_millis(100));
    OperationProgress {
        progress,
        total,
        message: message.to_owned(),
        started_payload: Cell::new(false),
    }
}

impl OperationProgress {
    pub fn inc(&self, bytes: u64) {
        if !self.started_payload.replace(true) {
            self.progress.disable_steady_tick();
            self.progress.set_length(self.total);
            self.progress.set_style(
                ProgressStyle::with_template(
                    "{msg:>10} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
                )
                .expect("progress template must be valid")
                .progress_chars("##-"),
            );
            self.progress.set_message(self.message.clone());
        }
        self.progress.inc(bytes);
    }

    pub fn finish(&self) {
        self.progress.finish_and_clear();
    }
}
