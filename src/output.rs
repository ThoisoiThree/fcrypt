use serde::Serialize;
use std::io::{self, Write};
use std::time::Duration;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, Copy)]
pub struct OutputOptions {
    pub quiet: bool,
    pub json: bool,
    pub no_progress: bool,
}

#[derive(Debug, Serialize)]
pub struct OperationReport {
    pub status: &'static str,
    pub operation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keys_dir: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub generated_keys: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl OperationReport {
    pub fn new(operation: &'static str) -> Self {
        Self {
            status: "ok",
            operation,
            mode: None,
            input: None,
            output: None,
            signature: None,
            files: Vec::new(),
            keys_dir: None,
            generated_keys: Vec::new(),
            verified: None,
            signer_key_id: None,
            data: None,
            warnings: Vec::new(),
        }
    }
}

/// One processed file in a multi-input encrypt or decrypt report.
#[derive(Debug, Serialize)]
pub struct FileReport {
    pub input: String,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Serialize)]
struct ErrorReport<'a> {
    status: &'static str,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    kind: &'static str,
    message: &'a str,
}

pub fn emit_success(
    options: OutputOptions,
    report: &OperationReport,
    lines: &[String],
) -> Result<()> {
    if options.json {
        let stdout = io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer(&mut stdout, report)
            .map_err(|error| AppError::Serialization(error.to_string()))?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
    } else if !options.quiet {
        for line in lines {
            println!("{line}");
        }
        for warning in &report.warnings {
            eprintln!("Warning: {warning}");
        }
    }
    Ok(())
}

/// Print one human-readable line immediately, e.g. after each file of a batch.
pub fn emit_line(options: OutputOptions, line: &str) {
    if !options.json && !options.quiet {
        println!("{line}");
    }
}

/// Format a byte count with binary units, e.g. `12.4 MiB`.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Format an elapsed time, e.g. `0.4s` or `2m 05s`.
pub fn format_duration(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else {
        format!("{}m {:02}s", secs / 60, secs % 60)
    }
}

pub fn emit_error(options: OutputOptions, error: &AppError) {
    if options.json {
        let report = ErrorReport {
            status: "error",
            error: ErrorBody {
                kind: error_kind(error),
                message: &error.to_string(),
            },
        };
        if serde_json::to_writer(io::stdout(), &report).is_ok() {
            let _ = writeln!(io::stdout());
        }
    } else {
        eprintln!("Error: {error}");
    }
}

fn error_kind(error: &AppError) -> &'static str {
    match error {
        AppError::Io(_) => "io",
        AppError::InvalidArgument(_) | AppError::InputNotRegularFile(_) => "invalid_argument",
        AppError::OutputExists(_) | AppError::OutputExistsNonInteractive(_) => "output_exists",
        AppError::PasswordMismatch | AppError::EmptyPassword => "password",
        AppError::DecryptionFailed
        | AppError::PasswordDecryptionFailed
        | AppError::KeyFileDecryptionFailed
        | AppError::AsymmetricAuthenticationFailed => "authentication",
        AppError::DecryptionMemoryLimitExceeded { .. } => "resource_limit",
        AppError::SignatureRequired
        | AppError::SignatureVerificationKeyRequired
        | AppError::SignatureVerificationFailed => "signature",
        AppError::AsymmetricUnavailable => "asymmetric_unavailable",
        AppError::BatchFile { source, .. } => error_kind(source),
        _ => "operation_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_use_binary_units() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1024), "1.0 KiB");
        assert_eq!(format_size(13 * 1024 * 1024 - 600 * 1024), "12.4 MiB");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn durations_switch_to_minutes() {
        assert_eq!(format_duration(Duration::from_millis(1800)), "1.8s");
        assert_eq!(format_duration(Duration::from_secs(125)), "2m 05s");
    }
}
