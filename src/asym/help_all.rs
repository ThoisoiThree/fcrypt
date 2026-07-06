pub fn print_help_all() {
    println!("{}", colorize_help_all(HELP_ALL));
}

pub const HELP_ALL: &str = r#"fcrypt full help

1. Purpose of fcrypt
  fcrypt encrypts and decrypts local files. The password-based symmetric mode
  is unchanged, and the asymmetric post-quantum mode writes versioned .fe
  envelopes.

2. Modes
  Symmetric mode:
    fcrypt encrypt <INPUT>
    fcrypt decrypt <INPUT>

  Asymmetric PQC .fe mode:
    fcrypt asym encrypt <INPUT>
    fcrypt asym decrypt <INPUT.fe>
    fcrypt asym sign <INPUT.fe>

3. Symmetric Mode
  encrypt and encode are aliases.
  decrypt and decode are aliases.
  The symmetric file format and password prompts are not changed.
  Symmetric encryption writes <INPUT>.fe by default.

4. Asymmetric PQC .fe Mode
  asym and assym are aliases. Help shows asym as the primary spelling.
  The mode always creates .fe files and uses:
    KEM 1: ML-KEM-1024
    KEM 2: HQC-256
    KDF: HKDF-SHA3-512
    AEAD: AES-256-GCM
    Signature: ML-DSA-87
    Hash: SHA3 family

5. Commands And Aliases
  fcrypt encrypt <INPUT> [OPTIONS]
  fcrypt encode  <INPUT> [OPTIONS]
  fcrypt decrypt <INPUT> [OPTIONS]
  fcrypt decode  <INPUT> [OPTIONS]

  fcrypt keygen <N>
  fcrypt keygen phrase <N> [OPTIONS]

  fcrypt asym encrypt <INPUT> [OPTIONS]
  fcrypt asym encode  <INPUT> [OPTIONS]
  fcrypt asym decrypt <INPUT.fe> [OPTIONS]
  fcrypt asym decode  <INPUT.fe> [OPTIONS]
  fcrypt asym sign    <INPUT.fe> [OPTIONS]

  fcrypt assym is accepted anywhere fcrypt asym is accepted.

6. Symmetric Options
  <INPUT>, -i, --input <FILE>
      Path to the input file.
  -p, --paranoic, --paranoid
      Use the higher-resource cascade mode.
  -f, --force
      Allow overwriting the output file.

7. Keygen Options
  fcrypt keygen <N>
      Generate a random password with N characters.
  fcrypt keygen phrase <N>
      Generate a random phrase with N words from the embedded EFF large wordlist.
  -sep, -s, --sep <SEP>
      Word separator for phrase generation. Defaults to '-'.

8. asym encrypt / encode Options
  -o, --output <FILE>
      Destination file. Defaults to <INPUT>.fe.
  -r, --recipient-public <FILE>
      Recipient public key bundle. If omitted, fcrypt generates a new
      recipient keypair automatically.
  -k, --keys-dir <DIR>
      Directory for generated or discovered keys. Defaults to
      <file_stem>_keys, for example report_keys/.
  -s, --sign
      Sign the result with ML-DSA-87.
  -S, --sign-key <FILE>
      Signing secret key. This automatically enables signing.
  -f, --force
      Allow overwriting the output file.

9. asym decrypt / decode Options
  -o, --output <FILE>
      Destination plaintext file. Defaults to <INPUT.fe without .fe>.
  -i, --identity <FILE>
      Recipient secret key bundle used for decryption.
  -k, --keys-dir <DIR>
      Directory for auto-discovering recipient secret keys.
  -v, --verify <FILE>
      Signing public key used to verify a signature.
  -R, --require-signature
      Require a valid signature. If no signature is present or verification
      cannot be completed, decryption fails.
  -f, --force
      Allow overwriting the output file.

10. asym sign Options
  -o, --output <FILE>
      Detached signature output. Defaults to <INPUT.fe>.sig unless --embed is set.
  -S, --sign-key <FILE>
      Signing secret key. If omitted, fcrypt generates a new signing keypair.
  -k, --keys-dir <DIR>
      Directory for generated signing keys. Defaults to <file_stem>_keys.
  -e, --embed
      Embed the signature into the .fe envelope.
  -f, --force
      Allow overwriting the output file.

11. Output File Format
  Both modes use .fe as the default filename extension.
  Symmetric mode keeps its existing binary format.
  Asymmetric mode writes a self-describing envelope:
    magic: FCRYPTFE
    version: 1
    header length
    CBOR header
    AES-256-GCM encrypted chunks

12. Where Keys Are Stored
  If -r/--recipient-public is not specified, recipient keys are generated
  automatically. By default, keys are saved in <file_stem>_keys:
    report.pdf -> report_keys/
  Override this with -k/--keys-dir. When --keys-dir is provided, fcrypt uses
  that directory directly and does not create a nested report_keys/ directory.

13. Recipient Key vs Signing Key
  recipient_default.sec is needed to decrypt matching .fe files.
  signer_mldsa87.sec is needed to create signatures.
  signer_mldsa87.pub is used with -v/--verify.
  -i/--identity selects a recipient secret key for decryption.

14. Examples
  Symmetric:
    fcrypt encrypt notes.txt
    fcrypt encode notes.txt
    fcrypt decrypt notes.txt.fe
    fcrypt decode notes.txt.fe

  Keygen:
    fcrypt keygen 32
    fcrypt keygen phrase 6
    fcrypt keygen phrase 6 -sep .

  Asymmetric with auto-generated keys:
    fcrypt asym encrypt report.pdf

  Creates:
    report.pdf.fe
    report_keys/
      <label8>_recipient_default.pub
      <label8>_recipient_default.sec

  Asymmetric with custom keys dir:
    fcrypt asym encrypt report.pdf -k ./keys

  Asymmetric with existing recipient public key:
    fcrypt asym encrypt report.pdf -r ./alice_recipient.pub

  Decrypt:
    fcrypt asym decrypt report.pdf.fe -i ./report_keys/a13f2c9b_recipient_default.sec

  Alias:
    fcrypt asym decode report.pdf.fe -i ./report_keys/a13f2c9b_recipient_default.sec

  Encrypt and sign with generated signing key:
    fcrypt asym encrypt report.pdf -s

  Encrypt and sign with existing signing key:
    fcrypt asym encrypt report.pdf -S ./sender_signer.sec

  Detached signing:
    fcrypt asym sign report.pdf.fe

  Embedded signing:
    fcrypt asym sign report.pdf.fe -e

  Decrypt and verify:
    fcrypt asym decrypt report.pdf.fe \
      -i ./report_keys/a13f2c9b_recipient_default.sec \
      -v ./sender_signer.pub

  Require signature:
    fcrypt asym decrypt report.pdf.fe \
      -i ./report_keys/a13f2c9b_recipient_default.sec \
      -v ./sender_signer.pub \
      -R

15. Security Notes
  .pub files are public and may be shared.
  .sec files are secret and must not be shared.

  recipient_default.sec can decrypt files encrypted for that recipient.
  signer_mldsa87.sec can create signatures but cannot decrypt files.

  Move .sec files to a safe location after encryption if needed.
  Anyone with recipient_default.sec can decrypt matching .fe files.
  Anyone with signer_mldsa87.sec can sign files as that signer.

  keygen phrase uses the embedded EFF large wordlist and cryptographically
  random word selection.

16. Troubleshooting
  If symmetric decrypt is used on an asymmetric .fe file:
    This file uses asymmetric .fe format.
    Use: fcrypt asym decrypt report.pdf.fe -i <recipient_default.sec>

  If asym decrypt is used on a symmetric-mode file:
    This file does not look like an asymmetric .fe file.
    Use the symmetric command if this is a password-encrypted file:
      fcrypt decrypt old.fcrypt

  If no identity key is found:
    No matching recipient secret key found.
    Use: fcrypt asym decrypt <file.fe> -i <recipient_default.sec>
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
