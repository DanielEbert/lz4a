#!/bin/bash

set -euox pipefail

# Set base directory
BASE_DIR=$(pwd)/test_data
rm -rf "$BASE_DIR"

# Create nested folder structure
mkdir -p "$BASE_DIR"/project/{docs/{specs,reports},src/{python,cpp},data/{raw,processed},bin}

# Create some text files with content
echo "Project Specification v1.0" > "$BASE_DIR/project/docs/specs/spec.txt"
echo "Weekly Report - Week 1" > "$BASE_DIR/project/docs/reports/report1.md"
echo "# Python Script" > "$BASE_DIR/project/src/python/script.py"
echo "// C++ Source Code" > "$BASE_DIR/project/src/cpp/main.cpp"
echo "Processed data summary" > "$BASE_DIR/project/data/processed/summary.csv"

# Create a small binary file
dd if=/dev/urandom of="$BASE_DIR/project/bin/executable.bin" bs=1M count=5

# Create large 1 GB files
dd if=/dev/zero of="$BASE_DIR/project/data/raw/largefile1.dat" bs=1M count=1024
dd if=/dev/zero of="$BASE_DIR/project/data/raw/largefile2.dat" bs=1M count=1024

# Show the structure
echo "Created folder and file structure:"
find "$BASE_DIR/project"

ARCHIVE_FILE="test_data.lz4a"
EXTRACT_DIR_SINGLE="/tmp/single_extract"
EXTRACT_DIR_ALL="/tmp/all_extract"

rm -f "$ARCHIVE_FILE"
rm -rf "$EXTRACT_DIR_SINGLE" "$EXTRACT_DIR_ALL"
mkdir -p "$EXTRACT_DIR_SINGLE" "$EXTRACT_DIR_ALL"

# Test adding files
./lz4d "$ARCHIVE_FILE" add -r "$BASE_DIR" "$BASE_DIR/project"

# Test listing files
./lz4d "$ARCHIVE_FILE" list

# Test extracting a single file
EXTRACT_FILE_PATH="project/docs/specs/spec.txt"
./lz4d "$ARCHIVE_FILE" extract "$EXTRACT_FILE_PATH" -o "$EXTRACT_DIR_SINGLE"

# Verify single file extraction
if ! cmp -s "$BASE_DIR/$EXTRACT_FILE_PATH" "$EXTRACT_DIR_SINGLE/$EXTRACT_FILE_PATH"; then
    echo "Error: Extracted single file content does not match original."
    exit 1
fi
echo "Single file extraction verified."

# Test extracting all files
./lz4d "$ARCHIVE_FILE" extract -o "$EXTRACT_DIR_ALL"

# Verify all files extraction
if ! diff -r --brief "$BASE_DIR/project" "$EXTRACT_DIR_ALL/project"; then
    echo "Error: Extracted archive content does not match original."
    diff -r "$BASE_DIR/project" "$EXTRACT_DIR_ALL/project"
    exit 1
fi
echo "Full archive extraction verified."

# Cleanup
rm -f "$ARCHIVE_FILE"
rm -rf "$BASE_DIR" "$EXTRACT_DIR_SINGLE" "$EXTRACT_DIR_ALL"

echo "success"
