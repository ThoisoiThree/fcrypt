use serde::Serialize;
use std::io::{self, Write};

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
            keys_dir: None,
            generated_keys: Vec::new(),
            verified: None,
            signer_key_id: None,
            data: None,
            warnings: Vec::new(),
        }
    }
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
        AppError::InvalidArgument(_) => "invalid_argument",
        AppError::OutputExists(_) | AppError::OutputExistsNonInteractive(_) => "output_exists",
        AppError::PasswordMismatch | AppError::EmptyPassword => "password",
        AppError::DecryptionFailed | AppError::AsymmetricAuthenticationFailed => "authentication",
        AppError::SignatureRequired
        | AppError::SignatureVerificationKeyRequired
        | AppError::SignatureVerificationFailed => "signature",
        AppError::AsymmetricUnavailable => "asymmetric_unavailable",
        _ => "operation_failed",
    }
}
