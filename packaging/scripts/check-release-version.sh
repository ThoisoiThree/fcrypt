#!/usr/bin/env bash
set -euo pipefail

EXPECTED_VERSION="${1#v}"

if [[ ! "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: $0 <X.Y.Z or vX.Y.Z>" >&2
  exit 2
fi

CARGO_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
LOCK_VERSION="$(awk '
  $0 == "name = \"fcrypt\"" { in_fcrypt = 1; next }
  in_fcrypt && /^version = / { gsub(/^version = "|"$/, ""); print; exit }
' Cargo.lock)"

if [[ "$CARGO_VERSION" != "$EXPECTED_VERSION" ]]; then
  echo "Cargo.toml has $CARGO_VERSION, expected $EXPECTED_VERSION" >&2
  exit 1
fi

if [[ "$LOCK_VERSION" != "$EXPECTED_VERSION" ]]; then
  echo "Cargo.lock has $LOCK_VERSION, expected $EXPECTED_VERSION" >&2
  exit 1
fi

node - "$EXPECTED_VERSION" package.json npm/packages/*/package.json <<'NODE'
const fs = require("fs");

const expected = process.argv[2];
const files = process.argv.slice(3);
let failed = false;

for (const file of files) {
  const pkg = JSON.parse(fs.readFileSync(file, "utf8"));
  if (pkg.version !== expected) {
    console.error(`${file} has ${pkg.version}, expected ${expected}`);
    failed = true;
  }

  if (file === "package.json") {
    for (const [name, version] of Object.entries(pkg.optionalDependencies || {})) {
      if (version !== expected) {
        console.error(`${file}: ${name} points to ${version}, expected ${expected}`);
        failed = true;
      }
    }
  }
}

if (failed) process.exit(1);
NODE

if ! grep -Fq "## [$EXPECTED_VERSION]" CHANGELOG.md; then
  echo "CHANGELOG.md has no [$EXPECTED_VERSION] release section" >&2
  exit 1
fi

BUILD_REVISION="$(sed -n 's/^const LIBOQS_REVISION: &str = "\([0-9a-f]*\)";/\1/p' \
  vendor/fcrypt-oqs-sys/build.rs)"
MANIFEST_REVISION="$(sed -n 's/^revision = "\([0-9a-f]*\)"/\1/p' \
  vendor/fcrypt-oqs-sys/Cargo.toml)"

if [[ -z "$BUILD_REVISION" || "$BUILD_REVISION" != "$MANIFEST_REVISION" ]]; then
  echo "liboqs revisions in build.rs and Cargo.toml do not match" >&2
  exit 1
fi

echo "Release metadata is consistent for v$EXPECTED_VERSION"
echo "Pinned liboqs revision: $BUILD_REVISION"
