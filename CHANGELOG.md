# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-07

### Added
- Added the opaque encrypted file container for password and asymmetric modes.
- Added post-quantum opaque recipient slots using ML-KEM-1024 and HQC-256.
- Added detached ML-DSA-87 signatures for opaque ciphertext files.
- Added `fcrypt keygen pair <name> [lifetime_days]` to generate recipient and signing keypairs together.
- Added fixed opaque v1 password KDF parameters: Argon2id, 128 MiB memory, time cost 3, parallelism 1.
- Added `docs/OPAQUE_FORMAT.md`.

### Changed
- Changed default encrypted output extension to `.bin`.
- Changed password decrypt to read chunk parameters from the encrypted manifest instead of runtime configuration.
- Changed password-slot encryption and decryption to use the same fixed opaque v1 Argon2id profile.
- Changed asymmetric signing to detached signatures for opaque ciphertext files.
- Bumped package metadata to `0.3.0`.

### Removed
- Removed the old cleartext-header encrypted file formats from the current decrypt path.
- Removed the `--paranoic` / `--paranoid` symmetric cascade mode.
- Removed embedded signatures for new opaque files.

### Security
- Opaque files no longer expose cleartext magic bytes, format version, algorithm identifiers, or recipient key identifiers.
- Payload chunk indexes now use `u64` nonces.
- Recipient key auto-discovery is bounded to avoid unbounded PQC decrypt attempts.
- Generated passphrases are returned in zeroizing storage.

### Compatibility
- `fcrypt` `0.3.0` cannot read files encrypted by `fcrypt` `0.2.0` or earlier. Use `fcrypt` `0.2.0` to read those old files.

## [0.2.0] - 2026-07-07

### Added
- Added GitHub Actions automation for signed `.deb` and `.rpm` packages, APT/RPM repository publication through GitHub Pages, and Sigstore bundle generation for package artifacts.
- Added npm package manifests, a Node.js launcher, and GitHub Actions automation for publishing prebuilt `fcrypt` binaries for Linux, macOS, and Windows on x64 and arm64.

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

[Unreleased]: https://github.com/ThoisoiThree/fcrypt/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ThoisoiThree/fcrypt/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ThoisoiThree/fcrypt/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/ThoisoiThree/fcrypt/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ThoisoiThree/fcrypt/compare/v0.1...v0.1.1
[0.1.0]: https://github.com/ThoisoiThree/fcrypt/releases/tag/v0.1
