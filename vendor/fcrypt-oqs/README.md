# Pinned Rust bindings to Open-Quantum-Safe's [liboqs][]

[![crates.io](https://img.shields.io/crates/v/fcrypt-oqs)](https://crates.io/crates/fcrypt-oqs)
[![docs.rs](https://img.shields.io/docsrs/fcrypt-oqs)](https://docs.rs/fcrypt-oqs)

This crate is the `fcrypt` project's API-compatible fork of `tectonic-oqs`.
It provides convenience wrappers around [liboqs][]. For the FFI layer and the
verified C-source pin, see `fcrypt-oqs-sys`.

[liboqs]: https://github.com/Open-Quantum-Safe/liboqs

## Features

* `std`: (default) build with `std` support. This adds handly `Display` and `Error` implementations
  to relevant types. If you want a `#![no_std]` library, disable this feature (and you
  probably want to disable the default features because they pull in OpenSSL through `oqs-sys`).
* `non_portable`: Don't build a portable library.
* `vendored`: (default) Controls the `fcrypt-oqs-sys/vendored` feature, which downloads, verifies, and builds the pinned liboqs source.
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
