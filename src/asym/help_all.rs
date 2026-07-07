pub fn print_help_all() {
    println!("{}", colorize_help_all(HELP_ALL));
}

pub const HELP_ALL: &str = r#"fcrypt full help

1. Purpose of fcrypt
  fcrypt encrypts and decrypts local files. Both password-based and
  asymmetric PQC encryption use the opaque container format.

2. Modes
  Symmetric mode:
    fcrypt encrypt <INPUT>
    fcrypt decrypt <INPUT>

  Asymmetric PQC opaque mode:
    fcrypt asym encrypt <INPUT>
    fcrypt asym decrypt <INPUT.bin>
    fcrypt asym sign <INPUT.bin>

3. Symmetric Mode
  encrypt and encode are aliases.
  decrypt and decode are aliases.
  Symmetric encryption writes <INPUT>.bin by default.
  There is no separate format flag.

4. Asymmetric PQC Opaque Mode
  asym and assym are aliases. Help shows asym as the primary spelling.
  The mode always creates opaque .bin files and uses:
    KEM 1: ML-KEM-1024
    KEM 2: HQC-256
    KDF: HKDF-SHA3-512
    AEAD: AES-256-GCM
    Signature: detached ML-DSA-87
    Hash: SHA3 family

5. Commands And Aliases
  fcrypt -ha
  fcrypt --help-all

  fcrypt encrypt <INPUT> [OPTIONS]
  fcrypt encode  <INPUT> [OPTIONS]
  fcrypt decrypt <INPUT> [OPTIONS]
  fcrypt decode  <INPUT> [OPTIONS]

  fcrypt keygen <N>
  fcrypt keygen phrase <N> [OPTIONS]
  fcrypt keygen pair <NAME> [LIFETIME_DAYS]

  fcrypt asym encrypt <INPUT> [OPTIONS]
  fcrypt asym encode  <INPUT> [OPTIONS]
  fcrypt asym decrypt <INPUT.bin> [OPTIONS]
  fcrypt asym decode  <INPUT.bin> [OPTIONS]
  fcrypt asym sign    <INPUT.bin> [OPTIONS]

  fcrypt assym is accepted anywhere fcrypt asym is accepted.
  -ha / --help-all is accepted from any command position and prints this page.

6. Symmetric Options
  <INPUT>, -i, --input <FILE>
      Path to the input file.
  -f, --force
      Allow overwriting the output file.

7. Keygen Options
  fcrypt keygen <N>
      Generate a random password with N characters.
  fcrypt keygen phrase <N>
      Generate a random phrase with N words from the embedded EFF large wordlist.
  -sep, -s, --sep <SEP>
      Word separator for phrase generation. Defaults to '-'.
  fcrypt keygen pair <NAME> [LIFETIME_DAYS]
      Generate four asymmetric key files in the current directory:
      <NAME>_recipient_default.pub
      <NAME>_recipient_default.sec
      <NAME>_signer_mldsa87.pub
      <NAME>_signer_mldsa87.sec
      Keys do not expire unless LIFETIME_DAYS is provided.

8. asym encrypt / encode Options
  -o, --output <FILE>
      Destination file. Defaults to <INPUT>.bin.
  -r, --recipient-public <FILE>
      Recipient public key bundle. If omitted, fcrypt generates a new
      recipient keypair automatically.
  -k, --keys-dir <DIR>
      Directory for generated or discovered keys. Defaults to
      <file_stem>_keys, for example report_keys/.
  -s, --sign
      Create a detached ML-DSA-87 signature next to the encrypted file.
  -S, --sign-key <FILE>
      Signing secret key. This automatically enables detached signing.
  -f, --force
      Allow overwriting the output file and detached signature.

9. asym decrypt / decode Options
  -o, --output <FILE>
      Destination plaintext file. Defaults to <INPUT.bin without .bin>.
  -i, --identity <FILE>
      Recipient secret key bundle used for decryption.
  -k, --keys-dir <DIR>
      Directory for auto-discovering recipient secret keys. Auto-discovery
      tries at most 32 matching recipient secret keys; use -i to select one.
  -v, --verify <FILE>
      Signing public key used to verify a detached signature.
  -R, --require-signature
      Require a valid detached signature before decrypting.
  -f, --force
      Allow overwriting the output file.

10. asym sign Options
  -o, --output <FILE>
      Detached signature output. Defaults to <INPUT.bin>.sig.
  -S, --sign-key <FILE>
      Signing secret key. If omitted, fcrypt generates a new signing keypair.
  -k, --keys-dir <DIR>
      Directory for generated signing keys. Defaults to <file_stem>_keys.
  -e, --embed
      Unsupported for opaque files.
  -f, --force
      Allow overwriting the signature file.

11. Output File Format
  Both modes use .bin as the default filename extension.
  The encrypted file has no magic bytes, cleartext version, cleartext
  algorithm identifiers, key id, or media mimicry.
  Format metadata is authenticated and encrypted inside an opaque prelude.

12. Where Keys Are Stored
  If -r/--recipient-public is not specified, recipient keys are generated
  automatically. By default, keys are saved in <file_stem>_keys:
    report.pdf -> report_keys/
  Override this with -k/--keys-dir. When --keys-dir is provided, fcrypt uses
  that directory directly and does not create a nested report_keys/ directory.

13. Recipient Key vs Signing Key
  recipient_default.sec is needed to decrypt matching opaque files.
  signer_mldsa87.sec is needed to create signatures.
  signer_mldsa87.pub is used with -v/--verify.
  -i/--identity selects a recipient secret key for decryption.
  keygen pair creates both recipient and signing keypairs at once.

14. Examples
  Symmetric:
    fcrypt encrypt notes.txt
    fcrypt encode notes.txt
    fcrypt decrypt notes.txt.bin
    fcrypt decode notes.txt.bin

  Keygen:
    fcrypt keygen 32
    fcrypt keygen phrase 6
    fcrypt keygen phrase 6 -sep .
    fcrypt keygen pair alice
    fcrypt keygen pair alice 365

  Asymmetric with auto-generated keys:
    fcrypt asym encrypt report.pdf

  Creates:
    report.pdf.bin
    report_keys/
      <label8>_recipient_default.pub
      <label8>_recipient_default.sec

  Asymmetric with custom keys dir:
    fcrypt asym encrypt report.pdf -k ./keys

  Asymmetric with existing recipient public key:
    fcrypt asym encrypt report.pdf -r ./alice_recipient.pub

  Decrypt:
    fcrypt asym decrypt report.pdf.bin -i ./report_keys/a13f2c9b_recipient_default.sec

  Alias:
    fcrypt asym decode report.pdf.bin -i ./report_keys/a13f2c9b_recipient_default.sec

  Encrypt and create a detached signature:
    fcrypt asym encrypt report.pdf -s

  Encrypt and sign with existing signing key:
    fcrypt asym encrypt report.pdf -S ./sender_signer.sec

  Detached signing:
    fcrypt asym sign report.pdf.bin

  Decrypt and verify:
    fcrypt asym decrypt report.pdf.bin \
      -i ./report_keys/a13f2c9b_recipient_default.sec \
      -v ./sender_signer.pub

  Require signature:
    fcrypt asym decrypt report.pdf.bin \
      -i ./report_keys/a13f2c9b_recipient_default.sec \
      -v ./sender_signer.pub \
      -R

15. Security Notes
  .pub files are public and may be shared.
  .sec files are secret and must not be shared.

  recipient_default.sec can decrypt files encrypted for that recipient.
  signer_mldsa87.sec can create signatures but cannot decrypt files.

  Move .sec files to a safe location after encryption if needed.
  The file does not reveal which recipient key should be tried.
  Anyone with signer_mldsa87.sec can sign files as that signer.

  keygen phrase uses the embedded EFF large wordlist and cryptographically
  random word selection.

16. Troubleshooting
  If no identity key is found:
    No matching recipient secret key found.
    Use: fcrypt asym decrypt <file.bin> -i <recipient_default.sec>

  If signature verification is requested:
    The detached signature must be next to the encrypted file as <file>.sig.
"#;

const SECTION_COLOR: &str = "\x1b[38;2;9;230;189m";
const OPTION_COLOR: &str = "\x1b[38;2;247;54;99m";
const RESET: &str = "\x1b[0m";

fn colorize_help_all(help: &str) -> String {
    let mut output = String::with_capacity(help.len() + 512);
    for line in help.lines() {
        if is_section_line(line) {
            output.push_str(SECTION_COLOR);
            output.push_str(line);
            output.push_str(RESET);
        } else if is_option_line(line) {
            output.push_str(OPTION_COLOR);
            output.push_str(line);
            output.push_str(RESET);
        } else {
            output.push_str(line);
        }
        output.push('\n');
    }
    output
}

fn is_section_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some((number, rest)) = trimmed.split_once(". ") else {
        return false;
    };
    !rest.is_empty() && number.chars().all(|c| c.is_ascii_digit())
}

fn is_option_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("<INPUT>") || trimmed.starts_with("-")
}
