#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

if ! command -v jq &> /dev/null; then
    echo "Error: jq is required to verify the manifest."
    exit 1
fi

echo "Verifying T0.json hashes..."

FAILED=0

while read -r path expected_hash; do
    if [ ! -f "$path" ]; then
        echo "MISSING: $path"
        FAILED=1
        continue
    fi

    actual_hash=$(sha256sum "$path" | awk '{print $1}')

    if [ "$actual_hash" = "$expected_hash" ]; then
        echo "OK: $path"
    else
        echo "FAIL: $path (expected $expected_hash, got $actual_hash)"
        FAILED=1
    fi
done < <(jq -r '.artifacts[] | "\(.path) \(.sha256)"' T0.json)

if [ $FAILED -ne 0 ]; then
    echo "Verification failed. Hashes do not match T0.json."
    exit 1
else
    echo "Verification passed. All file hashes match T0.json."
    exit 0
fi
