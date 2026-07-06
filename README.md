# fcrypt

`fcrypt` is a cross-platform Rust CLI for local file encryption, decryption, key generation, and post-quantum asymmetric file envelopes.

The crate name is `filecrypt`; the installed binary is `fcrypt`.

`fcrypt` is designed for large files. It processes data as authenticated chunks, writes outputs through temporary files, and finalizes results only after the operation succeeds.

## Highlights

- Password-based symmetric file encryption with AES-256-GCM and Argon2id.
- Optional high-cost symmetric `--paranoic` mode with AES-GCM-then-Serpent-EAX cascade encryption.
- Asymmetric post-quantum `.fe` envelopes using ML-KEM-1024 + HQC-256 to protect the file secret.
- AES-256-GCM streaming encryption for file contents.
- Optional ML-DSA-87 signatures for `.fe` files.
- Automatic recipient key generation when no recipient public key is provided.
- Hidden password prompts for symmetric encryption and decryption.
- Random password generation and Diceware-style passphrase generation from the embedded EFF large wordlist.
- Atomic output workflow: plaintext/ciphertext/key files are written to temp files first.
- npm packages with prebuilt binaries for Linux, macOS, and Windows on x64 and arm64.

## Security model

`fcrypt` has two separate encryption modes.

### Symmetric mode

Symmetric mode is password-based:

```text
password -> Argon2id -> AES-256-GCM key -> encrypted file
```

The password is entered through a hidden terminal prompt. The password is not stored in the encrypted file and is not logged.

### Asymmetric `.fe` mode

Asymmetric mode is recipient-key based:

```text
ML-KEM-1024 shared secret ┐
                          ├─ HKDF-SHA3-512 ── wrap key ── encrypt file_secret
HQC-256 shared secret ────┘

file_secret ── HKDF-SHA3-512 ── AES-256-GCM file key ── encrypted chunks
```

The file itself is encrypted with AES-256-GCM. ML-KEM-1024 and HQC-256 are used to protect the random file secret. This gives the `.fe` format two independent post-quantum KEM layers by default.

Optional signatures use ML-DSA-87:

```text
ciphertext + canonical envelope metadata -> ML-DSA-87 signature
```

A recipient key and a signing key are different keys:

- `*_recipient_default.pub` is shared with people who should be able to encrypt files for the recipient.
- `*_recipient_default.sec` decrypts matching `.fe` files and must remain secret.
- `*_signer_mldsa87.pub` is shared with people who should verify signatures.
- `*_signer_mldsa87.sec` creates signatures and must remain secret.

Never share `.sec` files.

## Install

### npm

```bash
npm install -g @thoisoithree/fcrypt
fcrypt --help
```

The npm package installs a small launcher and a prebuilt platform binary for the current OS/CPU.

Published platform packages:

- `@thoisoithree/fcrypt-linux-x64`
- `@thoisoithree/fcrypt-linux-arm64`
- `@thoisoithree/fcrypt-darwin-x64`
- `@thoisoithree/fcrypt-darwin-arm64`
- `@thoisoithree/fcrypt-win32-x64`
- `@thoisoithree/fcrypt-win32-arm64`

### GitHub release binaries

GitHub Releases provide raw binary files and `.sha256` checksum files for:

- Linux x64: `fcrypt-linux-x64`
- Linux arm64: `fcrypt-linux-arm64`
- macOS Intel: `fcrypt-darwin-x64`
- macOS Apple Silicon: `fcrypt-darwin-arm64`
- Windows x64: `fcrypt-win32-x64.exe`
- Windows arm64: `fcrypt-win32-arm64.exe`

### Build from source

```bash
cargo build --release --locked
```

Asymmetric PQC mode is enabled by default through the `pqc` feature and uses Open Quantum Safe `liboqs` through Rust `oqs` bindings. Building with PQC support can require:

- Rust stable
- C compiler
- CMake
- platform build tools

To build only the symmetric password-based mode:

```bash
cargo build --release --locked --no-default-features
```

When built without the `pqc` feature, `fcrypt asym ...` / `fcrypt assym ...` commands return a clear error and symmetric mode remains available.

Binary output:

- Linux/macOS: `target/release/fcrypt`
- Windows: `target/release/fcrypt.exe`

## Help

Short command-local help:

```bash
fcrypt -h
fcrypt encrypt -h
fcrypt decrypt -h
fcrypt asym -h
fcrypt asym encrypt -h
fcrypt asym decrypt -h
fcrypt asym sign -h
fcrypt keygen -h
fcrypt keygen phrase -h
```

Full help for every command, option, alias, and example:

```bash
fcrypt -ha
fcrypt --help-all
```

`-ha` / `--help-all` is accepted from subcommands too, for example:

```bash
fcrypt asym encrypt -ha
```

## Command overview

```bash
# Symmetric mode
fcrypt encrypt <INPUT> [OPTIONS]
fcrypt encode  <INPUT> [OPTIONS]
fcrypt decrypt <INPUT> [OPTIONS]
fcrypt decode  <INPUT> [OPTIONS]

# Asymmetric PQC .fe mode
fcrypt asym encrypt <INPUT> [OPTIONS]
fcrypt asym encode  <INPUT> [OPTIONS]
fcrypt asym decrypt <INPUT.fe> [OPTIONS]
fcrypt asym decode  <INPUT.fe> [OPTIONS]
fcrypt asym sign    <INPUT.fe> [OPTIONS]

# Alias
fcrypt assym ...    # accepted alias for fcrypt asym ...

# Key generation
fcrypt keygen <N>
fcrypt keygen phrase <N> [OPTIONS]
```

`encrypt` and `encode` are aliases. `decrypt` and `decode` are aliases. `asym` and `assym` are aliases.

## Symmetric password-based usage

Encrypt a file:

```bash
fcrypt encrypt report.pdf
```

Equivalent alias:

```bash
fcrypt encode report.pdf
```

The output is:

```text
report.pdf.fe
```

Decrypt:

```bash
fcrypt decrypt report.pdf.fe
```

Equivalent alias:

```bash
fcrypt decode report.pdf.fe
```

Force overwrite of an existing output file:

```bash
fcrypt decrypt report.pdf.fe --force
```

Use the high-resource symmetric cascade mode:

```bash
fcrypt encrypt --paranoic report.pdf
```

Aliases:

```bash
fcrypt encrypt --paranoid report.pdf
fcrypt encrypt -p report.pdf
```

Default `--paranoic` parameters use high Argon2id cost and AES-GCM-then-Serpent-EAX cascade encryption.

## Asymmetric PQC `.fe` usage

### Encrypt with automatically generated recipient keys

```bash
fcrypt asym encrypt report.pdf
```

Equivalent aliases:

```bash
fcrypt asym encode report.pdf
fcrypt assym encrypt report.pdf
fcrypt assym encode report.pdf
```

Output:

```text
report.pdf.fe
report_keys/
  <label8>_recipient_default.pub
  <label8>_recipient_default.sec
```

Example:

```text
report_keys/
  a13f2c9b_recipient_default.pub
  a13f2c9b_recipient_default.sec
```

Move the `.sec` file to a safe location if the encrypted file may be shared or archived with the folder.

### Encrypt for an existing recipient

```bash
fcrypt asym encrypt report.pdf -r ./alice_recipient.pub
```

Long option:

```bash
fcrypt asym encrypt report.pdf --recipient-public ./alice_recipient.pub
```

When `-r` / `--recipient-public` is provided, no new recipient keypair is generated.

### Choose a key directory

By default, keys are saved next to the input file in `<file_stem>_keys`:

```text
report.pdf        -> report_keys/
docs/report.pdf   -> docs/report_keys/
archive.tar.gz    -> archive.tar_keys/
```

Override it with `-k` / `--keys-dir`:

```bash
fcrypt asym encrypt report.pdf -k ./keys
```

When `--keys-dir` is provided, `fcrypt` uses that directory directly and does not create a nested `report_keys/` directory.

### Decrypt

```bash
fcrypt asym decrypt report.pdf.fe -i ./report_keys/a13f2c9b_recipient_default.sec
```

Equivalent alias:

```bash
fcrypt asym decode report.pdf.fe -i ./report_keys/a13f2c9b_recipient_default.sec
```

If `-i` / `--identity` is omitted, `fcrypt` tries to find a matching recipient secret key in the default or provided keys directory:

```bash
fcrypt asym decrypt report.pdf.fe
fcrypt asym decrypt report.pdf.fe -k ./report_keys
```

Matching is done by the full key id inside the key bundle, not by the short filename prefix.

### Encrypt and sign

Generate a signing key automatically and embed a signature in the `.fe` file:

```bash
fcrypt asym encrypt report.pdf -s
```

Generated files:

```text
report.pdf.fe
report_keys/
  <label8>_recipient_default.pub
  <label8>_recipient_default.sec
  <label8>_signer_mldsa87.pub
  <label8>_signer_mldsa87.sec
```

Sign with an existing signing key:

```bash
fcrypt asym encrypt report.pdf -S ./sender_signer.sec
```

`-S` / `--sign-key` automatically enables signing, so this is equivalent to `-s -S ./sender_signer.sec`.

### Sign an existing `.fe` file

Create a detached signature:

```bash
fcrypt asym sign report.pdf.fe
```

Output:

```text
report.pdf.fe.sig
```

Use an existing signing key:

```bash
fcrypt asym sign report.pdf.fe -S ./sender_signer.sec
```

Embed the signature into the `.fe` envelope:

```bash
fcrypt asym sign report.pdf.fe -e
```

### Verify signatures while decrypting

Verify with a signer public key:

```bash
fcrypt asym decrypt report.pdf.fe \
  -i ./report_keys/a13f2c9b_recipient_default.sec \
  -v ./sender_signer.pub
```

Require a valid signature:

```bash
fcrypt asym decrypt report.pdf.fe \
  -i ./report_keys/a13f2c9b_recipient_default.sec \
  -v ./sender_signer.pub \
  -R
```

If `-R` / `--require-signature` is used and no valid embedded or detached signature is available, decryption fails.

## Asymmetric options

### `asym encrypt` / `asym encode`

```text
-o, --output <FILE>             Destination .fe file. Defaults to <INPUT>.fe.
-r, --recipient-public <FILE>   Recipient public key bundle.
-k, --keys-dir <DIR>            Directory for generated or discovered keys.
-s, --sign                      Embed an ML-DSA-87 signature in the result.
-S, --sign-key <FILE>           Signing secret key. Implies --sign.
-f, --force                     Overwrite the destination file without asking.
```

### `asym decrypt` / `asym decode`

```text
-o, --output <FILE>             Destination plaintext file. Defaults to <INPUT.fe without .fe>.
-i, --identity <FILE>           Recipient secret key bundle.
-k, --keys-dir <DIR>            Directory for recipient secret key auto-discovery.
-v, --verify <FILE>             Signing public key for signature verification.
-R, --require-signature         Require a valid signature before decrypting.
-f, --force                     Overwrite the destination file without asking.
```

### `asym sign`

```text
-o, --output <FILE>             Detached signature output, or embedded output with --embed.
-S, --sign-key <FILE>           Signing secret key bundle. Generated if omitted.
-k, --keys-dir <DIR>            Directory for generated signing keys.
-e, --embed                     Embed the signature into the .fe envelope.
-f, --force                     Overwrite the destination file without asking.
```

## Key generation

### Random password

```bash
fcrypt keygen 32
```

`keygen <N>` writes a random password with `N` characters to stdout followed by a newline. `N` must be between 1 and 4096.

The password generator uses the operating system CSPRNG and this portable alphabet:

```text
A-Z a-z 0-9 ! # $ % & ( ) * + , - . / : ; < = > ? @ [ ] ^ _ { | } ~
```

### Random passphrase

Generate a phrase from the embedded EFF large wordlist:

```bash
fcrypt keygen phrase 7
```

Use a custom separator:

```bash
fcrypt keygen phrase 7 -sep .
fcrypt keygen phrase 7 --sep _
fcrypt keygen phrase 7 -s " "
```

`keygen phrase` uses the embedded EFF large wordlist with 7,776 words. Word selection is cryptographically random and uniform. The default separator is `-`.

Examples:

```bash
fcrypt keygen phrase 6
fcrypt keygen phrase 8 --sep _
```

## File formats

### Symmetric format

Symmetric encryption keeps the compact binary format used by the existing password-based mode:

```text
16 bytes: random salt
8 bytes:  random nonce prefix
8 bytes:  plaintext length, authenticated as AEAD AAD
encrypted AES-GCM chunks
```

The `--paranoic` symmetric mode uses a versioned binary metadata header and a cascade of AES-GCM and Serpent-EAX. The header is authenticated as AAD.

Compatibility note: `fcrypt` can decrypt legacy empty files produced before `0.1.1` that contain only the old 32-byte prefix. Those legacy empty files do not contain an authentication tag, so password correctness and integrity cannot be verified for that specific legacy case.

### Asymmetric `.fe` format

Asymmetric `.fe` files use a versioned envelope:

```text
magic:      FCRYPTFE
version:    1
header_len: u32
header:     CBOR HeaderV1
payload:    AES-256-GCM encrypted chunks
```

The current asymmetric suite id is:

```text
fcrypt-fe-v1-default-mlkem1024-hqc256-hkdfsha3-512-aes256gcm
```

The `.fe` header contains recipient KEM ciphertexts, wrapped file secret, AEAD metadata, header hash, and optional ML-DSA-87 signature metadata.

For compatibility, the reader also accepts the earlier asymmetric suite/mode name that used `paranoid` in internal metadata and key filenames. New files and new keys use `default`.

## Output naming

Encryption appends `.fe` to the full filename:

```text
report.pdf -> report.pdf.fe
```

Decryption removes `.fe` when present:

```text
report.pdf.fe -> report.pdf
```

Legacy `.enc` suffixes are still accepted by symmetric decryption:

```text
old-file.enc -> old-file
```

If the input has neither `.fe` nor `.enc`, decryption appends `.dec`:

```text
archive.bin -> archive.bin.dec
```

Source files are never modified in place.

## Release artifacts and package repositories

The release workflow builds raw binaries and SHA-256 checksum files for Linux, macOS, and Windows. Tagging a release with `vX.Y.Z` triggers GitHub Actions release automation.

APT and RPM repositories are published by the package repository workflow when repository signing secrets are configured. See [`docs/PACKAGE_REPOSITORIES.md`](docs/PACKAGE_REPOSITORIES.md) for setup and install commands.

Release process details are documented in [`RELEASE.md`](RELEASE.md).

## Development

Run tests:

```bash
cargo test --locked
```

Run clippy:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Build release:

```bash
cargo build --release --locked
```

Build without asymmetric PQC mode:

```bash
cargo build --release --locked --no-default-features
```

## Test coverage

The test suite covers:

- symmetric small-file, empty-file, and chunk-boundary roundtrips;
- wrong password, corrupted ciphertext, and truncated file failures;
- authenticated empty-file handling and legacy empty-file compatibility;
- asymmetric `.fe` roundtrips;
- explicit recipient public key encryption and secret key decryption;
- recipient key auto-discovery;
- embedded and detached ML-DSA-87 signatures;
- required signature failures;
- tamper detection for envelope/ciphertext/signature changes;
- output naming rules;
- overwrite behavior;
- random password and EFF wordlist passphrase generation;
- `-ha` / `--help-all` output.

## Security notes

- Keep `.sec` files private.
- Share only `.pub` files.
- A recipient `.sec` key can decrypt matching `.fe` files.
- A signer `.sec` key can create signatures as that signer.
- Use `-R` / `--require-signature` when authenticity is mandatory.
- Keep backups of recipient secret keys; losing the matching recipient `.sec` key makes `.fe` recovery impossible.
- Password-based files cannot be recovered without the original password.

## License

MIT. See [`LICENSE`](LICENSE).