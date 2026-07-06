use indicatif::{ProgressBar, ProgressStyle};
use std::io::IsTerminal;

pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    if total == 0 || !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }

    let pb = ProgressBar::new(total);
    let style = ProgressStyle::with_template(
        "{msg:>10} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
    )
    .expect("progress template must be valid")
    .progress_chars("##-");
    pb.set_style(style);
    pb.set_message(message.to_owned());
    pb
}
