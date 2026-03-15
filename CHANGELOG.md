# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-15

### Added
- Initial `fcrypt` CLI release.
- Password-based file encryption and decryption with AES-256-GCM.
- Argon2id key derivation with random per-file salt.
- Streaming chunked processing for large files with bounded memory usage.
- Hidden interactive password prompt and encryption confirmation prompt.
- Overwrite confirmation logic with `--force` override.
- Progress bar reporting bytes processed.
- Safe temp-file output workflow (finalize only after successful operation).
- Integration tests for roundtrip, edge cases, corruption/truncation, and naming logic.
