# fcrypt

`fcrypt` is a cross-platform Rust CLI for password-based file encryption and decryption.
The crate name is `filecrypt`, and the installed binary is `fcrypt`.

It is designed for large files and uses streaming I/O with bounded memory usage.

## Security

- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation with random 16-byte salt
- Random per-file nonce prefix
- No plaintext password storage or logging
- Password prompts are hidden
- Output is written to a temp file and finalized only on full success
- Decryption failures (wrong password, corruption, tampering, truncation) fail cleanly
- Empty files encrypted by `fcrypt` 0.1.1 and later include an authentication tag

## File format

Encrypted files are compact opaque binary data with no readable text header.

- 16 bytes: random salt
- 8 bytes: random nonce prefix
- 8 bytes: plaintext length (binary, authenticated as AEAD AAD)
- encrypted chunks (AES-GCM, fixed plaintext chunk size except final chunk)

This keeps the format compact while allowing strict structural validation and truncation detection.

Compatibility note: `fcrypt` can decrypt legacy empty files produced before 0.1.1 that contain only the 32-byte prefix. Those legacy empty files do not contain an authentication tag, so the password and integrity of that specific legacy empty-file case cannot be verified.

## Build

```bash
cargo build --release
```

Binary output:

- Linux/macOS: `target/release/fcrypt`
- Windows: `target/release/fcrypt.exe`

## Install from npm

The npm package installs a small launcher and a prebuilt platform binary for the current OS/CPU.

```bash
npm install -g @thoisoithree/fcrypt
fcrypt --help
```

Published platform packages:

- `@thoisoithree/fcrypt-linux-x64`
- `@thoisoithree/fcrypt-linux-arm64`
- `@thoisoithree/fcrypt-darwin-x64`
- `@thoisoithree/fcrypt-darwin-arm64`
- `@thoisoithree/fcrypt-win32-x64`
- `@thoisoithree/fcrypt-win32-arm64`

## Package repositories

APT and RPM repositories are published from the `Package Repositories` GitHub Actions workflow when repository GPG signing secrets are configured.

Ubuntu/Debian:

```bash
curl -fsSL https://thoisoithree.github.io/fcrypt/apt/fcrypt-packaging.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/fcrypt-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/fcrypt-archive-keyring.gpg] https://thoisoithree.github.io/fcrypt/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/fcrypt.list
sudo apt update
sudo apt install fcrypt
```

Fedora/RHEL-compatible:

```bash
sudo curl -fsSL -o /etc/yum.repos.d/fcrypt.repo \
  https://thoisoithree.github.io/fcrypt/rpm/fcrypt.repo
sudo dnf install fcrypt
```

Details: see `docs/PACKAGE_REPOSITORIES.md`.

## Usage

Show help:

```bash
cargo run --bin fcrypt -- --help
```

Encrypt:

```bash
cargo run --bin fcrypt -- encrypt --input /path/to/report.pdf
```

Decrypt:

```bash
cargo run --bin fcrypt -- decrypt --input /path/to/report.pdf.enc
```

Force overwrite (skip confirmation):

```bash
cargo run --bin fcrypt -- decrypt --input /path/to/report.pdf.enc --force
```

## Output naming rules

- Encryption appends `.enc` to the full filename:
  - `report.pdf` -> `report.pdf.enc`
- Decryption:
  - if input ends with `.enc`, that suffix is removed
    - `report.pdf.enc` -> `report.pdf`
  - otherwise `.dec` is appended
    - `archive.bin` -> `archive.bin.dec`

Source files are never modified in place.

## Tests

Run:

```bash
cargo test
```

Included tests cover:

- small-file roundtrip
- chunk-boundary roundtrips
- empty-file roundtrip
- empty-file authentication and legacy empty-file compatibility
- wrong password failure
- corrupted ciphertext failure
- truncated ciphertext failure
- filename mapping rules
- overwrite decision logic

## GitHub release

- CI (`.github/workflows/ci.yml`) validates format, clippy, tests, and release build on Linux/macOS/Windows.
- Tagging a release (`vX.Y.Z`) triggers `.github/workflows/release.yml`.
- Release workflow builds platform binaries, packages artifacts, creates SHA-256 checksums, and publishes a GitHub Release.
- Package repository workflow builds signed `.deb` and `.rpm` packages, attaches them to tag releases, and publishes APT/RPM repositories to GitHub Pages.

Detailed steps: see `RELEASE.md`.
