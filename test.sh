#!/bin/bash

set -euox pipefail

# Set base directory
BASE_DIR=$(pwd)/test_data

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

./lz4d test_data.lz4a add test_data
./lz4d test_data.lz4a list
./lz4d test_data.lz4a extract project/docs/specs/spec.txt -o /tmp
cat /tmp/project/docs/specs/spec.txt

rm test_data.lz4a

echo "success"
