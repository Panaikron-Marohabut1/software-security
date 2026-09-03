#!/usr/bin/env bash

set -e

TARGET="${1:-./vulnerable-repo}"
TARGET="$(realpath "$TARGET")"

echo "==> Semgrep (SAST)"
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$TARGET:/src" \
  semgrep/semgrep \
  semgrep --config p/default --config p/owasp-top-ten /src || true

echo
echo "==> Gitleaks (secret scanning)"
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$TARGET:/repo" \
  zricethezav/gitleaks:latest \
  detect --no-git -s /repo -v || true