# Security Policy

If you discover a security issue in `fcrypt`, please report it privately and do not open a public issue.

## Reporting

1. Provide a clear description of the issue.
2. Include reproduction steps and affected version(s).
3. Include impact details (data exposure, integrity risk, etc.).

## Scope

This project focuses on:

- correctness of encryption/decryption behavior
- integrity guarantees and tamper detection
- safe error handling without leaking sensitive data

## Paranoic mode

`fcrypt encrypt -p` / `--paranoic` uses higher Argon2id resource parameters by default: 1,048,576 KiB memory, time cost 6, and parallelism 4. It cascades each file chunk through AES-256-GCM and then Serpent-EAX. Paranoic files use a versioned binary metadata header with the paranoic flag, algorithms, chunk size, Argon2id parameters, plaintext length, salt, and nonce prefixes. That metadata is authenticated as AEAD associated data.

## Legacy compatibility

`fcrypt` 0.1.1 and later authenticate newly encrypted empty files with an AES-GCM tag.

For backward compatibility, `fcrypt` still decrypts legacy empty files created before 0.1.1 that contain only the 32-byte file prefix. Those legacy empty files do not contain an authentication tag, so their password and integrity cannot be verified. Re-encrypt empty files with 0.1.1 or later when authenticated empty-file handling is required.
