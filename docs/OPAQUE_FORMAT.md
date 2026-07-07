# Opaque File Format

This is the default encrypted file format starting in `fcrypt` `0.3.0`.
`fcrypt` `0.3.0` does not read pre-0.3.0 encrypted files. Use `fcrypt`
`0.2.0` when access to old encrypted files is required.

The default encrypted file format is intentionally random-looking. New files do
not contain magic bytes, cleartext version fields, cleartext algorithm names, or
cleartext recipient identifiers.

The fixed outer layout is:

```text
32 bytes        file nonce
8 * 16384      recipient slots
4112 bytes     encrypted manifest
rest           encrypted payload chunks
```

The manifest is encrypted with a random manifest key recovered from one
recipient slot. The manifest contains the internal format version, plaintext
length, chunk size, chunk count, tag length, and random payload file secret.

Recipient slots are fixed-size random-looking records. Password slots derive a
slot key with the opaque v1 Argon2id profile and the file nonce:

```text
memory:      131072 KiB (128 MiB)
time cost:   3
parallelism: 1
output:      32 bytes
```

These KDF parameters are part of the opaque v1 format. Future parameter changes
must use a new slot profile or a new opaque format version. PQC slots store
ML-KEM-1024 and HQC-256 ciphertexts followed by an AEAD-wrapped manifest key.
Empty slots are random bytes. The reader tries the supplied password or
available recipient secret keys against every slot.

Payload chunks use AES-256-GCM. Chunk nonces are:

```text
4-byte per-file nonce base || 8-byte big-endian chunk index
```

Chunk AAD binds each chunk to the encrypted manifest hash, chunk index, total
plaintext length, total chunk count, chunk plaintext length, and final flag.

Mimicry/steganographic wrappers are intentionally not part of this format.
