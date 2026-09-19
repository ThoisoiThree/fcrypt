# Pinned FFI bindings to [Open Quantum Safe][oqs]'s [liboqs][]

[![crates.io](https://img.shields.io/crates/v/fcrypt-oqs-sys)](https://crates.io/crates/fcrypt-oqs-sys)
[![docs.rs](https://img.shields.io/docsrs/fcrypt-oqs-sys)](https://docs.rs/fcrypt-oqs-sys)

This crate is the `fcrypt` project's security-maintained fork of
`tectonic-oqs-sys`. It provides unsafe FFI bindings to [liboqs][] and pins the
downloaded C source to commit
`282809f06dccf6893980035cb11f319684d10d52`. The build verifies the commit and
worktree cleanliness before compiling fresh or cached sources.

## Features

* `vendored`: Download, verify, and compile the pinned liboqs source instead of linking to the system version.
* `openssl` (default): Compile with OpenSSL features (mostly symmetric cryptography)
* `non_portable`: Don't build a portable library.
* `kems` (default): Compile with all KEMs enabled
    * `bike`  (only on non-Windows)
    * `classic_mceliece`
    * `frodokem`
    * `hqc`
    * `kyber`
    * `ml_kem`
    * `ntruprime`
* `sigs` (default): Compile with all signature schemes enabled
    * `cross`
    * `dilithium`
    * `falcon`
    * `mayo`
    * `ml_dsa`
    * `sphincs`: SPHINCS+
    * `uov`

[oqs]: https://openquantumsafe.org
[liboqs]: https://github.com/Open-Quantum-Safe/liboqs
