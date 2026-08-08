#!/bin/bash
# verify_build_dir.sh — checks a local build directory against
# MANIFEST.md5 (the current, authoritative set of .c files for this
# project). Run this from inside the directory containing your
# downloaded .c files, with MANIFEST.md5 also present there.
#
# Catches two distinct failure modes that caused real, confusing
# errors earlier in this project's history:
#   1. A file present but with STALE content (an older download that
#      predates a fix — this is what caused the tds_parser/http1_parser
#      phantom-warning report and the openvpn/xmpp linker error, both
#      traced back to this exact cause).
#   2. A file MISSING entirely (would show as a compiler/linker error
#      for missing symbols, similar in symptom to stale content).
#
# Usage:
#   cp MANIFEST.md5 /path/to/your/build/dir/
#   cd /path/to/your/build/dir/
#   bash verify_build_dir.sh

set -u

if [ ! -f MANIFEST.md5 ]; then
    echo "ERROR: MANIFEST.md5 not found in the current directory."
    echo "Copy it alongside your .c files first, then re-run this script."
    exit 1
fi

echo "=== Checking for missing or stale files ==="
missing=0
stale=0
ok=0

while IFS='  ' read -r expected_hash filename; do
    # Handle the two-space separator robustly regardless of shell IFS quirks
    filename=$(echo "$expected_hash $filename" | awk '{print $2}')
    expected_hash=$(echo "$expected_hash $filename" | awk '{print $1}')

    if [ ! -f "$filename" ]; then
        echo "  MISSING: $filename"
        missing=$((missing+1))
        continue
    fi

    actual_hash=$(md5sum "$filename" | awk '{print $1}')
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "  STALE:   $filename (content doesn't match the current project — re-download this one)"
        stale=$((stale+1))
    else
        ok=$((ok+1))
    fi
done < MANIFEST.md5

echo ""
echo "=== Checking for extra .c files not in the manifest ==="
extra=0
for f in *.c; do
    if ! grep -q "  $f\$" MANIFEST.md5; then
        echo "  EXTRA: $f (not part of the current project — if this is an old"
        echo "         copy of a file that's since been renamed or removed,"
        echo "         it can silently shadow the real one during compilation)"
        extra=$((extra+1))
    fi
done

echo ""
echo "=== Summary ==="
echo "OK: $ok   Stale: $stale   Missing: $missing   Extra: $extra"
if [ "$stale" -eq 0 ] && [ "$missing" -eq 0 ] && [ "$extra" -eq 0 ]; then
    echo "Build directory matches the current project exactly."
    exit 0
else
    echo "Build directory does NOT match — re-download the flagged files before compiling."
    exit 1
fi
