# Security Policy

If you discover a security issue in `fcrypt`, please report it privately and do not open a public issue.

`einspiegel@protonmail.com`

## Reporting

1. Provide a clear description of the issue.
2. Include reproduction steps and affected version(s).
3. Include impact details (data exposure, integrity risk, etc.).

## Scope

This project focuses on:

- correctness of encryption/decryption behavior
- integrity guarantees and tamper detection
- safe error handling without leaking sensitive data

## Opaque format

New encrypted files use the opaque container format. Files do not start with magic bytes, a cleartext version, cleartext algorithm identifiers, or cleartext recipient identifiers. Format metadata is authenticated and encrypted in the manifest, and payload chunk indexes use `u64` nonces.

## Legacy compatibility

Opaque files authenticate empty inputs with an AEAD tag. Legacy pre-opaque containers are not auto-detected by the current decrypt path because the format intentionally avoids cleartext headers.

`fcrypt` `0.3.0` does not provide backward compatibility for files encrypted by `fcrypt` `0.2.0` or earlier. Use `fcrypt` `0.2.0` to read those old files.
