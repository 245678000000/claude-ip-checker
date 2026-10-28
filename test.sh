#!/bin/zsh
set -euo pipefail
cd "${0:A:h}"
node --test Tests/*.test.js
export GOCACHE="/tmp/claude-ip-go-cache"
go test ./...
go vet ./...
CACHE="/tmp/clang-module-cache"
TEST_BIN="$(mktemp "${TMPDIR:-/tmp}/claude-ip-tests.XXXXXX")"
trap 'rm -f "$TEST_BIN"' EXIT
swiftc -target arm64-apple-macosx14.0 -module-cache-path "$CACHE" Sources/NetworkDetector.swift Tests/NativeDiagnosticsTests.swift -o "$TEST_BIN"
"$TEST_BIN"
swiftc -typecheck -target arm64-apple-macosx14.0 -module-cache-path "$CACHE" Sources/NetworkDetector.swift Sources/AppMain.swift
