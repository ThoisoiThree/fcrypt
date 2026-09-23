# Release Process

An expanded step-by-step tutorial is available in
`docs/DEPLOY.md`.

## 1. Prepare release

1. Ensure `CHANGELOG.md` has a section for the new version.
2. Record the shipped liboqs commit in `CHANGELOG.md` and confirm it matches
   `LIBOQS_REVISION` in `vendor/fcrypt-oqs-sys/build.rs` and
   `package.metadata.liboqs.revision` in that crate's `Cargo.toml`.
3. Bump `version` in `Cargo.toml`, root `package.json`, and every `npm/packages/*/package.json`.
4. Run checks:
   - `cargo fmt --all -- --check`
   - `cargo clippy --locked --all-targets --all-features -- -D warnings`
   - `cargo clippy --locked --all-targets --no-default-features -- -D warnings`
   - `cargo test --locked --all-features`
   - `cargo test --locked --no-default-features`
   - `cargo build --release --locked`
   - `cargo package --manifest-path vendor/fcrypt-oqs-sys/Cargo.toml --list`
   - `cargo package --manifest-path vendor/fcrypt-oqs/Cargo.toml --list`
   - `cargo package -p fcrypt --list`
   - Run the publish dry-runs in the dependency order described in section 4.

## 2. Create tag

1. Commit release changes.
2. Create and push a version tag:
   - `git tag vX.Y.Z`
   - `git push origin vX.Y.Z`

## 3. GitHub release

After pushing a `v*` tag, GitHub Actions `release.yml` will:

1. Build release binaries on:
   - Linux (`x86_64-unknown-linux-gnu`)
   - Linux ARM64 (`aarch64-unknown-linux-gnu`)
   - macOS Intel (`x86_64-apple-darwin`)
   - macOS Apple Silicon (`aarch64-apple-darwin`)
   - Windows x64 (`x86_64-pc-windows-msvc`)
   - Windows ARM64 (`aarch64-pc-windows-msvc`)
2. Attach raw binary files and SHA-256 checksum files.
3. Publish a GitHub Release with attached artifacts.

## 4. crates.io

GitHub Actions `crates.yml` publishes `fcrypt-oqs-sys`, `fcrypt-oqs`, and
`fcrypt` in dependency order. It waits for each dependency to appear in the
crates.io index and skips an exact version that is already published.

Before the first run:

1. Create the GitHub environment `crates-publish`.
2. Add a crates.io API token as its `CARGO_REGISTRY_TOKEN` secret.
3. Require reviewers for that environment when practical.

Pushing a `vX.Y.Z` tag starts the workflow. Manual fallback commands and
first-publication details are documented in `docs/DEPLOY.md`.

Published crate versions cannot be overwritten or deleted. A broken version can
only be yanked, so do not publish until the dry run and release checks pass.

## 5. Package repositories

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

## 6. npm packages

GitHub Actions `npm.yml` publishes:

1. `@thoisoithree/fcrypt-linux-x64`
2. `@thoisoithree/fcrypt-linux-arm64`
3. `@thoisoithree/fcrypt-darwin-x64`
4. `@thoisoithree/fcrypt-darwin-arm64`
5. `@thoisoithree/fcrypt-win32-x64`
6. `@thoisoithree/fcrypt-win32-arm64`
7. `@thoisoithree/fcrypt`

Publishing should use npm Trusted Publishing with GitHub Actions OIDC, not a long-lived npm token stored in repository secrets.

Initial setup:

1. Publish each package once manually, or from a private bootstrap workflow that only you control.
2. On npmjs.com, open each package and configure Settings -> Trusted publishing:
   - Provider: GitHub Actions
   - Organization/user: `ThoisoiThree`
   - Repository: `fcrypt`
   - Workflow filename: `npm.yml`
   - Environment name: `npm-publish`
   - Allowed action: `npm publish`
3. In GitHub repository settings, create environment `npm-publish` and require trusted reviewers for deployments.
4. In package Settings -> Publishing access, enable two-factor authentication and disallow tokens.

After that, pushing a `vX.Y.Z` tag runs `npm.yml`. The workflow publishes platform packages first, then the main launcher package. Re-running the workflow skips package versions that already exist in npm.

If trusted publishing was configured with the wrong repository owner casing, recreate it:

```bash
npm trust list @thoisoithree/fcrypt-linux-x64
npm trust revoke @thoisoithree/fcrypt-linux-x64 --id <trust-id>
npm trust github @thoisoithree/fcrypt-linux-x64 --repo ThoisoiThree/fcrypt --file npm.yml --env npm-publish --allow-publish --yes
```

Repeat for each package.
