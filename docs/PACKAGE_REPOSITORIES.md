# Package Repositories

`fcrypt` can publish signed APT and RPM repositories from GitHub Actions.

The workflow is `.github/workflows/packages.yml`. It builds:

- `fcrypt_<version>_amd64.deb`
- `fcrypt-<version>-1.x86_64.rpm`
- SHA-256 sums
- detached GPG signatures
- Sigstore keyless signature bundles
- APT repository metadata for GitHub Pages
- RPM repository metadata with `createrepo_c`

## Required repository settings

Enable GitHub Pages with the source set to GitHub Actions.

Add these repository secrets:

- `PACKAGING_GPG_PRIVATE_KEY`: ASCII-armored private GPG key used for package and repository signing.
- `PACKAGING_GPG_PASSPHRASE`: passphrase for that private key.

The workflow fails intentionally if the secrets are missing. Sigstore signing is keyless and uses GitHub Actions OIDC, but APT and RPM repositories still need a stable GPG key that users can trust.

## Ubuntu/Debian install

```bash
curl -fsSL https://thoisoithree.github.io/fcrypt/apt/fcrypt-packaging.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/fcrypt-archive-keyring.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/fcrypt-archive-keyring.gpg] https://thoisoithree.github.io/fcrypt/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/fcrypt.list

sudo apt update
sudo apt install fcrypt
```

## Fedora/RHEL-compatible install

```bash
sudo curl -fsSL -o /etc/yum.repos.d/fcrypt.repo \
  https://thoisoithree.github.io/fcrypt/rpm/fcrypt.repo

sudo dnf install fcrypt
```

The RPM repository enables both package GPG checks and repository metadata GPG checks.

## Publishing

The package repository workflow runs on:

- any pushed `v*` tag
- manual `workflow_dispatch`

On tag builds, package assets and signatures are also attached to the GitHub Release for that tag.
