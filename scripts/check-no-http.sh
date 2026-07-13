#!/usr/bin/env bash
# Security invariant §4.7: EnvVault contains no networking code.
#
# Why not just grep Cargo.lock? The lockfile is platform-agnostic: it lists
# dependencies for every conceivable target, including ones we never ship.
# (tauri depends on reqwest *only* for Android/iOS — it is never compiled
# into a desktop binary.) The truthful check is to resolve the dependency
# graph for each desktop target we actually ship and assert no HTTP client
# appears in it. `-e normal` excludes build/dev dependencies, which do not
# ship in the binary.
set -euo pipefail

cd "$(dirname "$0")/.."

BANNED='^(reqwest|hyper|hyper-util|ureq|curl|curl-sys|isahc|attohttpc|surf) '

TARGETS=(
  aarch64-apple-darwin
  x86_64-apple-darwin
  x86_64-pc-windows-msvc
  aarch64-pc-windows-msvc
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
)

fail=0
for target in "${TARGETS[@]}"; do
  found=$(cargo tree --workspace --target "$target" -e normal --prefix none 2>/dev/null \
    | sort -u | grep -E "$BANNED" || true)
  if [ -n "$found" ]; then
    echo "FAIL [$target]: HTTP client crate(s) in the shipped dependency graph:" >&2
    echo "$found" >&2
    fail=1
  else
    echo "OK   [$target]: no HTTP client crates in the shipped dependency graph."
  fi
done

exit $fail
