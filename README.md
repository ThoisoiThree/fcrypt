# fcrypt

`fcrypt` is a cross-platform Rust CLI for local file encryption, decryption,
key generation, and post-quantum asymmetric encryption.

The crate name is `filecrypt`; the installed binary is `fcrypt`.

`fcrypt` is designed for large files. It processes data as authenticated
chunks, writes outputs through temporary files, and finalizes results only after
the operation succeeds.

## Release 0.3.x compatibility notice

Version `0.3.0` introduced the opaque `.bin` container format, retained by the
`0.3.x` releases. It does **not** provide backward compatibility for pre-0.3.0
encrypted files.

To read old files created by `fcrypt` `0.2.0` or earlier, use `fcrypt` version
`0.2.0`.

## Highlights

- Opaque password-based encrypted files with no cleartext magic bytes, version,
  algorithm identifiers, or recipient identifiers.
- Password slots use a fixed opaque v1 Argon2id profile: 128 MiB, time cost 3,
  parallelism 1.
- Post-quantum asymmetric encryption with ML-KEM-1024 + HQC-256 recipient
  slots.
- AES-256-GCM streaming payload encryption with `u64` chunk indexes.
- Detached ML-DSA-87 signatures for opaque ciphertext files.
- Explicit identity creation with `identity create <name>` for recipient and
  signing key pairs. The legacy `asym encrypt` workflow retains its historical
  automatic key generation behavior.
- Random password generation and Diceware-style passphrase generation from the
  embedded EFF large wordlist.
- Atomic output workflow: plaintext, ciphertext, signature, and key files are
  written through temporary files first.
- npm packages with prebuilt binaries for Linux, macOS, and Windows on x64 and
  arm64.

## Security model

### Password encryption

Password mode uses the opaque container format:

```text
password -> fixed Argon2id profile -> password slot -> manifest key
manifest key -> encrypted manifest -> file secret
file secret -> HKDF-SHA3-512 -> AES-256-GCM payload chunks
```

The password is entered through a hidden terminal prompt. The password is not
stored in the encrypted file and is not logged.

### Asymmetric encryption

Asymmetric mode uses recipient keys:

```text
ML-KEM-1024 shared secret ┐
                          ├─ HKDF-SHA3-512 ── slot key ── manifest key
HQC-256 shared secret ────┘

manifest key -> encrypted manifest -> file secret
file secret  -> HKDF-SHA3-512 -> AES-256-GCM payload chunks
```

ML-KEM-1024 and HQC-256 provide two independent post-quantum KEM layers for
recipient access.

Optional detached signatures use ML-DSA-87:

```text
opaque ciphertext transcript -> ML-DSA-87 signature -> <ciphertext>.sig
```

A recipient key and a signing key are different keys:

- `*_recipient_default.pub` is shared with people who should encrypt files for
  the recipient.
- `*_recipient_default.sec` decrypts matching opaque files and must remain
  secret.
- `*_signer_mldsa87.pub` is shared with people who should verify signatures.
- `*_signer_mldsa87.sec` creates signatures and must remain secret.

Never share `.sec` files.

## Install

### npm

```bash
npm install -g @thoisoithree/fcrypt
fcrypt --help
```

The npm package installs a small launcher and a prebuilt platform binary for
the current OS/CPU.

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

Asymmetric PQC mode is enabled by default through the `pqc` feature and uses
Open Quantum Safe `liboqs` through Rust `oqs` bindings. Building with PQC
support can require:

- Rust stable
- C compiler
- CMake
- platform build tools

To build only the password-based mode:

```bash
cargo build --release --locked --no-default-features
```

When built without the `pqc` feature, `fcrypt asym ...` / `fcrypt assym ...`
commands return a clear error and password mode remains available.

## Help

Short command-local help:

```bash
fcrypt -h
fcrypt encrypt -h
fcrypt decrypt -h
fcrypt identity -h
fcrypt sign -h
fcrypt verify -h
```

Full help for every command, option, alias, and example:

```bash
fcrypt help-all
```

The compatibility forms `-ha` and `--help-all` are also accepted. They are
handled before command parsing, except after `--`, so a file literally named
`-ha` remains a valid input path.

```bash
fcrypt --help-all
```

## Command overview

```bash
# Recommended commands
fcrypt encrypt <INPUT> [-o <OUTPUT>]
fcrypt decrypt <INPUT.bin> [-o <OUTPUT>]
fcrypt sign <INPUT.bin> --key <SIGNER.SEC>
fcrypt verify <INPUT.bin> --key <SIGNER.PUB>
fcrypt identity create <NAME>
fcrypt identity list
fcrypt identity inspect <KEY>
fcrypt password generate --length <N>
fcrypt phrase generate --words <N>

# Compatibility commands
fcrypt asym ...
fcrypt assym ...
fcrypt keygen ...
```

`encrypt` and `encode` are aliases. `decrypt` and `decode` are aliases. The
legacy `asym`, `assym`, and `keygen` command groups remain supported.

## Password-based usage

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
report.pdf.bin
```

Decrypt:

```bash
fcrypt decrypt report.pdf.bin
```

Equivalent alias:

```bash
fcrypt decode report.pdf.bin
```

Force overwrite of an existing output file:

```bash
fcrypt decrypt report.pdf.bin --force
```

Choose a specific output path:

```bash
fcrypt encrypt report.pdf --output archive.bin
fcrypt decrypt archive.bin --output report-restored.pdf
```

For automation, read a password from a protected file. A single trailing LF or
CRLF is removed; other whitespace remains part of the password:

```bash
fcrypt encrypt report.pdf --password-file ./fcrypt-password.txt --json
fcrypt decrypt report.pdf.bin --password-file ./fcrypt-password.txt --quiet
```

`--json` emits one machine-readable result to stdout. `--quiet` suppresses
normal success messages and progress, while `--no-progress` keeps final output
but hides progress indicators. Passwords must never be supplied as command-line
arguments.

## Asymmetric PQC opaque usage

### Recommended recipient-key workflow

```bash
fcrypt identity create alice
fcrypt encrypt report.pdf --recipient ./alice_recipient_default.pub
```

The unified command never creates a recipient key silently. Use
`--new-identity <NAME>` when intentional one-off identity creation is desired.
Back up the generated recipient `.sec` file: without it, encrypted data cannot
be recovered.

Sign and verify ciphertexts without decrypting:

```bash
fcrypt sign report.pdf.bin --key ./alice_signer_mldsa87.sec
fcrypt verify report.pdf.bin --key ./alice_signer_mldsa87.pub
fcrypt decrypt report.pdf.bin \
  --identity ./alice_recipient_default.sec \
  --verify ./alice_signer_mldsa87.pub
```

### Generate named recipient and signing keys

Generate four key files in the current directory:

```bash
fcrypt keygen pair alice
```

Output files:

```text
alice_recipient_default.pub
alice_recipient_default.sec
alice_signer_mldsa87.pub
alice_signer_mldsa87.sec
```

Keys are non-expiring by default. To create keys with a lifetime in days:

```bash
fcrypt keygen pair alice 365
```

### Encrypt for an existing recipient

```bash
fcrypt asym encrypt report.pdf -r ./alice_recipient_default.pub
```

Long option:

```bash
fcrypt asym encrypt report.pdf --recipient-public ./alice_recipient_default.pub
```

When `-r` / `--recipient-public` is provided, no new recipient keypair is
generated.

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

When `--keys-dir` is provided, `fcrypt` uses that directory directly and does
not create a nested `report_keys/` directory.

### Decrypt

```bash
fcrypt asym decrypt report.pdf.bin -i ./report_keys/a13f2c9b_recipient_default.sec
```

Equivalent alias:

```bash
fcrypt asym decode report.pdf.bin -i ./report_keys/a13f2c9b_recipient_default.sec
```

If `-i` / `--identity` is omitted, `fcrypt` tries available recipient secret
keys in the default or provided keys directory:

```bash
fcrypt asym decrypt report.pdf.bin
fcrypt asym decrypt report.pdf.bin -k ./report_keys
```

Opaque ciphertexts do not reveal which recipient key should be tried.
Auto-discovery is therefore bounded to 32 matching recipient secret key files;
use `-i` to select a specific key when needed.

### Encrypt and sign

Generate a signing key automatically and create a detached signature:

```bash
fcrypt asym encrypt report.pdf -s
```

Generated files:

```text
report.pdf.bin
report.pdf.bin.sig
report_keys/
  <label8>_recipient_default.pub
  <label8>_recipient_default.sec
  <label8>_signer_mldsa87.pub
  <label8>_signer_mldsa87.sec
```

Sign with an existing signing key:

```bash
fcrypt asym encrypt report.pdf -S ./alice_signer_mldsa87.sec
```

`-S` / `--sign-key` automatically enables signing, so this is equivalent to
`-s -S ./alice_signer_mldsa87.sec`.

### Sign an existing opaque file

Create a detached signature:

```bash
fcrypt asym sign report.pdf.bin
```

Output:

```text
report.pdf.bin.sig
```

Use an existing signing key:

```bash
fcrypt asym sign report.pdf.bin -S ./alice_signer_mldsa87.sec
```

Embedded signatures are not supported for opaque files.

### Verify signatures while decrypting

Verify with a signer public key:

```bash
fcrypt asym decrypt report.pdf.bin \
  -i ./report_keys/a13f2c9b_recipient_default.sec \
  -v ./alice_signer_mldsa87.pub
```

Require a valid signature:

```bash
fcrypt asym decrypt report.pdf.bin \
  -i ./report_keys/a13f2c9b_recipient_default.sec \
  -v ./alice_signer_mldsa87.pub \
  -R
```

When `--verify <signer.pub>` is used, a valid detached signature is required
before decryption. The legacy `-R` / `--require-signature` option remains
accepted for compatibility and still requires a verification key.

## Options

### `encrypt` / `encode`

```text
<INPUT>, -i, --input <FILE>     Path to the input file.
-f, --force                     Overwrite the destination file without asking.
```

### `decrypt` / `decode`

```text
<INPUT>, -i, --input <FILE>     Path to the input file.
-f, --force                     Overwrite the destination file without asking.
```

### `asym encrypt` / `asym encode`

```text
-o, --output <FILE>             Destination .bin file. Defaults to <INPUT>.bin.
-r, --recipient-public <FILE>   Recipient public key bundle.
-k, --keys-dir <DIR>            Directory for generated or discovered keys.
-s, --sign                      Create a detached ML-DSA-87 signature.
-S, --sign-key <FILE>           Signing secret key. Implies --sign.
-f, --force                     Overwrite output and signature files without asking.
```

### `asym decrypt` / `asym decode`

```text
-o, --output <FILE>             Destination plaintext file. Defaults to <INPUT.bin without .bin>.
-i, --identity <FILE>           Recipient secret key bundle.
-k, --keys-dir <DIR>            Directory for recipient secret key auto-discovery.
-v, --verify <FILE>             Signing public key for signature verification.
-R, --require-signature         Require a valid signature before decrypting.
-f, --force                     Overwrite the destination file without asking.
```

### `asym sign`

```text
-o, --output <FILE>             Detached signature output. Defaults to <INPUT>.sig.
-S, --sign-key <FILE>           Signing secret key bundle. Generated if omitted.
-k, --keys-dir <DIR>            Directory for generated signing keys.
-e, --embed                     Unsupported for opaque files.
-f, --force                     Overwrite the signature file without asking.
```

## Key generation

### Random password

```bash
fcrypt password generate --length 32
fcrypt password generate --length 32 -c
fcrypt password generate --length 32 -b
```

`password generate` writes a random password with `N` characters to stdout followed by
a newline. `N` must be between 1 and 4096.
`-c`/`--compatible` restricts special characters to the widely accepted
`!@#$%^&*_-+=` set. `-b`/`--base64` Base64-encodes the generated password
before writing it. The legacy `-b64` spelling remains accepted.

The password generator uses the operating system CSPRNG and this portable
alphabet:

```text
A-Z a-z 0-9 ! # $ % & ( ) * + , - . / : ; < = > ? @ [ ] ^ _ { | } ~
```

### Random passphrase

Generate a phrase from the embedded EFF large wordlist:

```bash
fcrypt phrase generate --words 7
```

Use a custom separator:

```bash
fcrypt phrase generate --words 7 --separator .
fcrypt phrase generate --words 7 --separator _
fcrypt phrase generate --words 7 --separator " "
```

`keygen phrase` uses the embedded EFF large wordlist with 7,776 words. Word
selection is cryptographically random and uniform. The default separator is
`-`.

### Named asymmetric key pairs

```bash
fcrypt identity create alice
fcrypt identity create alice --lifetime-days 365
```

`identity create` writes one recipient keypair and one signing keypair. The optional
lifetime is in days. The key filename prefix accepts ASCII letters, digits,
`.`, `_`, and `-`, and must not start with `.`.

## Opaque file format

Both password and asymmetric encryption use the same opaque `.bin` container.
The outer file has no magic bytes, cleartext format version, cleartext
algorithm identifiers, cleartext KDF parameters, or cleartext recipient key id.

Fixed outer layout:

```text
32 bytes        file nonce
8 * 16384      recipient slots
4112 bytes     encrypted manifest
rest           encrypted payload chunks
```

The encrypted manifest contains the internal format version, plaintext length,
chunk size, chunk count, tag length, and random payload file secret.

Password slots use opaque v1 Argon2id:

```text
memory:      131072 KiB (128 MiB)
time cost:   3
parallelism: 1
output:      32 bytes
```

Payload chunks use AES-256-GCM. Chunk nonces are:

```text
4-byte per-file nonce base || 8-byte big-endian chunk index
```

See [`docs/OPAQUE_FORMAT.md`](docs/OPAQUE_FORMAT.md) for implementation-level
details.

## Output naming

Encryption appends `.bin` to the full filename:

```text
report.pdf -> report.pdf.bin
```

Decryption removes `.bin` when present:

```text
report.pdf.bin -> report.pdf
```

Legacy `.enc` suffixes are accepted only for output-path mapping:

```text
old-file.enc -> old-file
```

They do not imply legacy file format support in `0.3.x`.

If the input has neither `.bin` nor `.enc`, decryption appends `.dec`:

```text
archive.dat -> archive.dat.dec
```

Source files are never modified in place.

## Release artifacts and package repositories

The release workflow builds raw binaries and SHA-256 checksum files for Linux,
macOS, and Windows. Tagging a release with `vX.Y.Z` triggers GitHub Actions
release automation.

APT and RPM repositories are published by the package repository workflow when
repository signing secrets are configured. See
[`docs/PACKAGE_REPOSITORIES.md`](docs/PACKAGE_REPOSITORIES.md) for setup and
install commands.

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

- password small-file, empty-file, and chunk-boundary roundtrips;
- wrong password, corrupted ciphertext, and truncated file failures;
- opaque prelude tamper detection;
- fixed password KDF profile behavior;
- asymmetric opaque roundtrips;
- explicit recipient public key encryption and secret key decryption;
- bounded recipient key auto-discovery;
- detached ML-DSA-87 signatures;
- standalone signature verification and unified password/PQC CLI workflows;
- required signature failures;
- named `keygen pair` generation with and without lifetime;
- output naming rules;
- overwrite behavior;
- random password and EFF wordlist passphrase generation;
- `help-all` and compatibility `-ha` / `--help-all` output.

## Security notes

- Keep `.sec` files private.
- Share only `.pub` files.
- A recipient `.sec` key can decrypt matching opaque files.
- A signer `.sec` key can create signatures as that signer.
- Use `--verify <signer.pub>` when authenticity is mandatory during decryption.
- Expired recipient secret keys remain usable for archival decryption, and
  expired signing public keys remain usable for historical verification. Expired
  recipient public keys and signing secret keys cannot be used for new work.
- Keep backups of recipient secret keys; losing the matching recipient `.sec`
  key makes recovery impossible.
- Password-based files cannot be recovered without the original password.
- `fcrypt` `0.3.x` cannot read pre-0.3.0 encrypted files. Use version `0.2.0`
  for those files.

## License

MIT. See [`LICENSE`](LICENSE).
