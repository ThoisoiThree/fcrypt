# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added GitHub Actions automation for signed `.deb` and `.rpm` packages, APT/RPM repository publication through GitHub Pages, and Sigstore bundle generation for package artifacts.

## [0.1.2] - 2026-05-17

### Security
- Updated `indicatif` to `0.18.4` to remove the unmaintained transitive `number_prefix` dependency reported by `cargo audit`.

## [0.1.1] - 2026-05-17

### Fixed
- Authenticate newly encrypted empty files with an AES-GCM tag while preserving legacy empty-file compatibility.
- Avoid non-forced output clobbering races by finalizing temp files with no-clobber persistence.
- Replace forced outputs without deleting the destination before the final persist step.

### Security
- Updated `rand` to `0.8.6`.

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

[Unreleased]: https://github.com/ThoisoiThree/fcrypt/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/ThoisoiThree/fcrypt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ThoisoiThree/fcrypt/compare/v0.1...v0.1.1
[0.1.0]: https://github.com/ThoisoiThree/fcrypt/releases/tag/v0.1
