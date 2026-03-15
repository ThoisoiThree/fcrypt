# Contributing

## Local checks

Run before opening a pull request:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
```

## Commit style

- Keep commits focused and small.
- Update tests for behavior changes.
- Update `CHANGELOG.md` for user-visible changes.
