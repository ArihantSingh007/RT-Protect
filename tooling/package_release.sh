#!/usr/bin/env bash
# tooling/package_release.sh
#
# Builds a Release configuration, runs the full test suite, and packages
# the CLI tool plus licensing/attribution docs into a dated tarball under
# dist/. Fails closed: any build or test failure aborts packaging rather
# than shipping a package nobody has confirmed works.
#
# Usage: ./tooling/package_release.sh [build-dir]
# Run from the repository root.

set -euo pipefail

BUILD_DIR="${1:-build-release-pkg}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "== rtprotect release packaging =="
echo "Repository root: $REPO_ROOT"
echo "Build directory: $BUILD_DIR"
echo

echo "-- Configuring (Release, hardening ON) --"
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DRTPROTECT_HARDEN_RELEASE=ON

echo
echo "-- Building --"
cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || echo 4)"

echo
echo "-- Running full test suite (packaging aborts on any failure) --"
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo
echo "-- Assembling package --"
VERSION="$(date -u +%Y%m%d)"
PKG_NAME="rtprotect-${VERSION}-linux-x86_64"
PKG_DIR="dist/${PKG_NAME}"
rm -rf "dist/${PKG_NAME}"
mkdir -p "$PKG_DIR/bin"

cp "$BUILD_DIR/tooling/rtprotect-tool" "$PKG_DIR/bin/"
if [ -f "$BUILD_DIR/bench/rtprotect-bench" ]; then
  cp "$BUILD_DIR/bench/rtprotect-bench" "$PKG_DIR/bin/"
fi
cp README.md "$PKG_DIR/"
cp -r docs "$PKG_DIR/"

echo
echo "-- Verifying the packaged tool runs --"
# Captured into a variable rather than piped directly into `head`: with
# `set -o pipefail` active, piping a multi-line writer into `head -1`
# causes the writer to receive SIGPIPE once `head` closes the pipe after
# its first line, which pipefail then reports as a pipeline failure and
# `set -e` aborts the whole script -- a real bug this script had on its
# first version (caught by actually running it, not just reading it).
# rtprotect-tool's no-argument invocation is ALSO expected to exit
# non-zero (it's printing usage, not succeeding) -- `|| true` on the
# command substitution keeps that from tripping `set -e` for a reason
# unrelated to the SIGPIPE issue above.
tool_output="$("$PKG_DIR/bin/rtprotect-tool" 2>&1 || true)"
echo "$tool_output" | head -1

echo
echo "-- Creating archive --"
tar -C dist -czf "dist/${PKG_NAME}.tar.gz" "${PKG_NAME}"

echo
echo "Done: dist/${PKG_NAME}.tar.gz"
ls -la "dist/${PKG_NAME}.tar.gz"
