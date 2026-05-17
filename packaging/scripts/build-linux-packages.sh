#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

OUT_DIR="${1:-dist/packages}"
MODE="${2:-all}"
WORK_DIR="${FCRYPT_PACKAGE_WORK_DIR:-${TMPDIR:-/tmp}/fcrypt-package-work}"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)"

if [[ -z "$VERSION" ]]; then
  echo "Could not determine Cargo package version" >&2
  exit 1
fi

if [[ "$MODE" != "all" && "$MODE" != "deb" && "$MODE" != "rpm" ]]; then
  echo "Usage: $0 [out-dir] [all|deb|rpm]" >&2
  exit 1
fi

if [[ ! -x target/release/fcrypt ]]; then
  echo "target/release/fcrypt does not exist; run cargo build --release --locked first" >&2
  exit 1
fi

if [[ "$MODE" == "all" ]]; then
  rm -rf "$OUT_DIR" "$WORK_DIR"
else
  rm -rf "$WORK_DIR/$MODE"
fi
mkdir -p "$OUT_DIR" "$WORK_DIR"

if [[ "$MODE" == "all" || "$MODE" == "deb" ]]; then
  DEB_ROOT="$WORK_DIR/deb/debroot"
  rm -rf "$WORK_DIR/deb"
  install -d -m 0755 "$DEB_ROOT/DEBIAN"
  install -d -m 0755 "$DEB_ROOT/usr/bin"
  install -d -m 0755 "$DEB_ROOT/usr/share/doc/fcrypt"

  install -m 0755 target/release/fcrypt "$DEB_ROOT/usr/bin/fcrypt"
  install -m 0644 README.md "$DEB_ROOT/usr/share/doc/fcrypt/README.md"
  install -m 0644 CHANGELOG.md "$DEB_ROOT/usr/share/doc/fcrypt/CHANGELOG.md"
  install -m 0644 LICENSE "$DEB_ROOT/usr/share/doc/fcrypt/copyright"

  cat > "$DEB_ROOT/DEBIAN/control" <<EOF
Package: fcrypt
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Maintainer: ThoisoiThree <noreply@github.com>
Homepage: https://github.com/ThoisoiThree/fcrypt
Description: Password-based file encryption and decryption CLI
 fcrypt is a command-line utility for password-based file encryption and
 decryption. It uses AES-256-GCM authenticated encryption and Argon2id
 password-based key derivation.
EOF

  chmod 0755 "$DEB_ROOT/DEBIAN"
  chmod 0644 "$DEB_ROOT/DEBIAN/control"
  dpkg-deb --root-owner-group --build "$DEB_ROOT" "$OUT_DIR/fcrypt_${VERSION}_amd64.deb"
fi

if [[ "$MODE" == "all" || "$MODE" == "rpm" ]]; then
  RPM_TOP="$WORK_DIR/rpm/rpmbuild"
  rm -rf "$WORK_DIR/rpm"
  install -d -m 0755 "$RPM_TOP/SOURCES" "$RPM_TOP/SPECS" "$RPM_TOP/BUILD" "$RPM_TOP/RPMS" "$RPM_TOP/SRPMS"
  install -m 0755 target/release/fcrypt "$RPM_TOP/SOURCES/fcrypt"
  install -m 0644 README.md "$RPM_TOP/SOURCES/README.md"
  install -m 0644 CHANGELOG.md "$RPM_TOP/SOURCES/CHANGELOG.md"
  install -m 0644 LICENSE "$RPM_TOP/SOURCES/LICENSE"
  install -m 0644 packaging/rpm/fcrypt.spec "$RPM_TOP/SPECS/fcrypt.spec"
  chmod 0644 "$RPM_TOP/SOURCES/README.md" "$RPM_TOP/SOURCES/CHANGELOG.md" "$RPM_TOP/SOURCES/LICENSE"
  RPM_TOP_ABS="$(cd "$RPM_TOP" && pwd)"

  rpmbuild -bb "$RPM_TOP/SPECS/fcrypt.spec" \
    --define "_topdir $RPM_TOP_ABS" \
    --define "pkg_version $VERSION"

  find "$RPM_TOP/RPMS" -type f -name '*.rpm' -exec cp {} "$OUT_DIR/" \;
fi

shopt -s nullglob
artifacts=("$OUT_DIR"/*.deb "$OUT_DIR"/*.rpm)
if (( ${#artifacts[@]} == 0 )); then
  echo "No package artifacts were produced" >&2
  exit 1
fi

(cd "$OUT_DIR" && sha256sum *.deb *.rpm > SHA256SUMS)
