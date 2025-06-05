# lz4a - Lz4 Archive

Like zip but uses lz4 for compression.

~~~
Usage: lz4a <archive> <command> [options]

Commands:
  add <files_or_dirs...> Add file(s) or directories to archive.
                         Uses thread pool for batch compression.
  extract [files...]     Extract file(s) from archive (all if no files specified).
                         Uses streaming decompression.
  list                   List files in archive

Options:
  -o <dir>               Output directory for extraction.
  -r <base>              Store added file paths relative to <base>.

Examples:
  lz4a archive.lz4a add file1.txt path/to/folder/
  lz4a archive.lz4a add -r /a/b /a/b/c/file1.txt
                         (adds as c/file1.txt in archive)
  lz4a archive.lz4a list
  lz4a archive.lz4a extract -o output_dir/
  lz4a archive.lz4a extract file1.txt path/in/archive/file.txt -o output_dir/
~~~


### TODO

- allow custom tmpdir
