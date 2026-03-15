# Release Process

## 1. Prepare release

1. Ensure `CHANGELOG.md` has a section for the new version.
2. Bump `version` in `Cargo.toml`.
3. Run checks:
   - `cargo fmt --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test --locked`
   - `cargo build --release --locked`

## 2. Create tag

1. Commit release changes.
2. Create and push a version tag:
   - `git tag vX.Y.Z`
   - `git push origin vX.Y.Z`

## 3. GitHub release

After pushing a `v*` tag, GitHub Actions `release.yml` will:

1. Build release binaries on:
   - Linux (`x86_64-unknown-linux-gnu`)
   - macOS (`x86_64-apple-darwin`)
   - Windows (`x86_64-pc-windows-msvc`)
2. Package binaries and generate SHA-256 checksum files.
3. Publish a GitHub Release with attached artifacts.
