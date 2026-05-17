#!/usr/bin/env bash
set -euo pipefail

PKG_DIR="${1:-dist/packages}"
PUBLIC_DIR="${2:-public}"
BASE_URL="${3:-https://thoisoithree.github.io/fcrypt}"

if [[ -z "${GPG_KEY_ID:-}" ]]; then
  echo "GPG_KEY_ID is required" >&2
  exit 1
fi

if [[ -z "${PACKAGING_GPG_PASSPHRASE:-}" ]]; then
  echo "PACKAGING_GPG_PASSPHRASE is required" >&2
  exit 1
fi

rm -rf "$PUBLIC_DIR"
mkdir -p "$PUBLIC_DIR"
touch "$PUBLIC_DIR/.nojekyll"

gpg --armor --export "$GPG_KEY_ID" > "$PUBLIC_DIR/fcrypt-packaging.asc"

APT_ROOT="$PUBLIC_DIR/apt"
install -d -m 0755 "$APT_ROOT/pool/main/f/fcrypt"
install -d -m 0755 "$APT_ROOT/dists/stable/main/binary-amd64"
cp "$PKG_DIR"/*.deb "$APT_ROOT/pool/main/f/fcrypt/"
cp "$PUBLIC_DIR/fcrypt-packaging.asc" "$APT_ROOT/fcrypt-packaging.asc"

pushd "$APT_ROOT" >/dev/null
dpkg-scanpackages --arch amd64 pool > dists/stable/main/binary-amd64/Packages
gzip -9 -k -f dists/stable/main/binary-amd64/Packages
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin="fcrypt" \
  -o APT::FTPArchive::Release::Label="fcrypt" \
  -o APT::FTPArchive::Release::Suite="stable" \
  -o APT::FTPArchive::Release::Codename="stable" \
  -o APT::FTPArchive::Release::Architectures="amd64" \
  -o APT::FTPArchive::Release::Components="main" \
  -o APT::FTPArchive::Release::Description="fcrypt APT repository" \
  release dists/stable > dists/stable/Release
gpg --batch --yes --pinentry-mode loopback --passphrase "$PACKAGING_GPG_PASSPHRASE" \
  --local-user "$GPG_KEY_ID" --clearsign \
  -o dists/stable/InRelease dists/stable/Release
gpg --batch --yes --pinentry-mode loopback --passphrase "$PACKAGING_GPG_PASSPHRASE" \
  --local-user "$GPG_KEY_ID" --armor --detach-sign \
  -o dists/stable/Release.gpg dists/stable/Release
popd >/dev/null

RPM_ROOT="$PUBLIC_DIR/rpm"
install -d -m 0755 "$RPM_ROOT/x86_64"
cp "$PKG_DIR"/*.rpm "$RPM_ROOT/x86_64/"
cp "$PUBLIC_DIR/fcrypt-packaging.asc" "$RPM_ROOT/fcrypt-packaging.asc"
createrepo_c "$RPM_ROOT/x86_64"
gpg --batch --yes --pinentry-mode loopback --passphrase "$PACKAGING_GPG_PASSPHRASE" \
  --local-user "$GPG_KEY_ID" --armor --detach-sign \
  -o "$RPM_ROOT/x86_64/repodata/repomd.xml.asc" \
  "$RPM_ROOT/x86_64/repodata/repomd.xml"

cat > "$RPM_ROOT/fcrypt.repo" <<EOF
[fcrypt]
name=fcrypt packages
baseurl=$BASE_URL/rpm/x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$BASE_URL/rpm/fcrypt-packaging.asc
metadata_expire=1h
EOF

cat > "$PUBLIC_DIR/index.html" <<EOF
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>fcrypt package repositories</title>
</head>
<body>
  <h1>fcrypt package repositories</h1>
  <h2>Ubuntu/Debian</h2>
  <pre>curl -fsSL $BASE_URL/apt/fcrypt-packaging.asc | sudo gpg --dearmor -o /usr/share/keyrings/fcrypt-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/fcrypt-archive-keyring.gpg] $BASE_URL/apt stable main" | sudo tee /etc/apt/sources.list.d/fcrypt.list
sudo apt update
sudo apt install fcrypt</pre>
  <h2>Fedora/RHEL-compatible</h2>
  <pre>sudo curl -fsSL -o /etc/yum.repos.d/fcrypt.repo $BASE_URL/rpm/fcrypt.repo
sudo dnf install fcrypt</pre>
</body>
</html>
EOF
