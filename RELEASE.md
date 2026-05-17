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

## 4. Package repositories

GitHub Actions `packages.yml` can build and publish Linux package repositories:

1. Build `fcrypt_<version>_amd64.deb`.
2. Build `fcrypt-<version>-1.x86_64.rpm`.
3. Sign package artifacts with detached GPG signatures and Sigstore keyless bundles.
4. Publish APT repository metadata under GitHub Pages `/apt`.
5. Publish RPM repository metadata under GitHub Pages `/rpm`.
6. Attach package artifacts and signatures to tag releases.

Before enabling this workflow, configure GitHub Pages to use GitHub Actions and add repository secrets:

- `PACKAGING_GPG_PRIVATE_KEY`
- `PACKAGING_GPG_PASSPHRASE`

Detailed setup and install commands are in `docs/PACKAGE_REPOSITORIES.md`.
