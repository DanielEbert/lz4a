#include "lz4.h"
#include "lz4frame.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;

class ThreadPool {
   public:
    ThreadPool(size_t num_threads) : stop_pool(false) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] { return this->stop_pool || !this->tasks.empty(); });
                        if (this->stop_pool && this->tasks.empty()) {
                            return;
                        }
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::invoke_result<F, Args...>::type> {
        using return_type = typename std::invoke_result<F, Args...>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...));

        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop_pool) throw std::runtime_error("enqueue on stopped ThreadPool");
            tasks.emplace([task]() { (*task)(); });
        }
        condition.notify_one();
        return res;
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop_pool = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            if (worker.joinable()) worker.join();
        }
    }

   private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop_pool;
};

// Helper to ensure RAII for LZ4 contexts
template <typename T_CTX_PTR, LZ4F_errorCode_t (*CreateFunc)(T_CTX_PTR*, unsigned),
          LZ4F_errorCode_t (*FreeFunc)(T_CTX_PTR)>
class LZ4ContextManager {
    T_CTX_PTR ctx_ = nullptr;

   public:
    LZ4ContextManager() {
        LZ4F_errorCode_t err = CreateFunc(&ctx_, LZ4F_VERSION);
        if (LZ4F_isError(err)) {
            throw std::runtime_error("LZ4 context creation failed: " + std::string(LZ4F_getErrorName(err)));
        }
    }
    ~LZ4ContextManager() {
        if (ctx_) FreeFunc(ctx_);
    }

    T_CTX_PTR get() const { return ctx_; }
    operator T_CTX_PTR() const { return ctx_; }
};

using LZ4FCompressionContext =
    LZ4ContextManager<LZ4F_compressionContext_t, LZ4F_createCompressionContext, LZ4F_freeCompressionContext>;
using LZ4FDecompressionContext =
    LZ4ContextManager<LZ4F_decompressionContext_t, LZ4F_createDecompressionContext, LZ4F_freeDecompressionContext>;

// RAII Temporary Directory Helper
class TemporaryDirectory {
    fs::path path_;

   public:
    TemporaryDirectory() {
        fs::path temp_base = fs::temp_directory_path();
        uint64_t timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                 std::chrono::high_resolution_clock::now().time_since_epoch())
                                 .count();
        std::string unique_name = "lz4arch_temp_" + std::to_string(timestamp);
        path_ = temp_base / unique_name;
        if (!fs::create_directory(path_)) {
            throw std::runtime_error("Failed to create temporary directory: " + path_.string());
        }
    }
    ~TemporaryDirectory() {
        if (fs::exists(path_)) {
            std::error_code ec;
            fs::remove_all(path_, ec);
            if (ec) {
                std::cerr << "Warning: Failed to remove temporary directory " << path_.string() << ": " << ec.message()
                          << std::endl;
            }
        }
    }

    const fs::path& path() const { return path_; }
};

void write_uint32_le(std::ostream& os, uint32_t value) {
    uint8_t bytes[4];
    bytes[0] = value & 0xFF;
    bytes[1] = (value >> 8) & 0xFF;
    bytes[2] = (value >> 16) & 0xFF;
    bytes[3] = (value >> 24) & 0xFF;
    os.write(reinterpret_cast<char*>(bytes), 4);
}

void write_uint64_le(std::ostream& os, uint64_t value) {
    uint8_t bytes[8];
    for (int i = 0; i < 8; i++) bytes[i] = (value >> (i * 8)) & 0xFF;
    os.write(reinterpret_cast<char*>(bytes), 8);
}

uint32_t read_uint32_le(std::istream& is) {
    uint8_t bytes[4];
    is.read(reinterpret_cast<char*>(bytes), 4);
    if (is.gcount() != 4) throw std::runtime_error("Read error or EOF reading uint32_t");
    return bytes[0] | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
}

uint64_t read_uint64_le(std::istream& is) {
    uint8_t bytes[8];
    is.read(reinterpret_cast<char*>(bytes), 8);
    if (is.gcount() != 8) throw std::runtime_error("Read error or EOF reading uint64_t");
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) result |= (uint64_t(bytes[i]) << (i * 8));
    return result;
}

struct FileEntry {
    uint64_t offset;
    uint64_t compressed_size;
    uint64_t original_size;

    FileEntry() = default;
    FileEntry(uint64_t off, uint64_t comp_size, uint64_t orig_size)
        : offset(off), compressed_size(comp_size), original_size(orig_size) {}
};

uint64_t compress_stream_to_stream(std::istream& in_s, std::ostream& out_s, uint64_t original_size_hint);

class LZ4Archive {
   public:
    static constexpr size_t STREAM_BUFFER_SIZE = 64 * 1024;

   private:
    static constexpr char MAGIC[8] = {'L', 'Z', '4', 'A', 'R', 'C', 'H', '1'};
    static constexpr size_t MAGIC_LEN = 8;
    static constexpr size_t DIRECTORY_SIZE_LEN = 8;
    static constexpr uint64_t MAX_DIR_SERIALIZED_IN_MEMORY = 256 * 1024 * 1024;

    std::string archive_path;
    std::unordered_map<std::string, FileEntry> directory;
    std::unique_ptr<ThreadPool> pool;  // Thread pool for batch operations

    uint64_t decompress_stream_data(std::istream& in_s, std::ostream& out_s, uint64_t compressed_size_to_read) {
        LZ4FDecompressionContext dctx;
        std::vector<char> in_buf(STREAM_BUFFER_SIZE);
        std::vector<char> out_buf(STREAM_BUFFER_SIZE);
        uint64_t total_original_size = 0;
        uint64_t total_compressed_read = 0;
        bool end_of_frame = false;

        while (total_compressed_read < compressed_size_to_read && !end_of_frame) {
            size_t to_read = std::min(in_buf.size(), (size_t)(compressed_size_to_read - total_compressed_read));
            in_s.read(in_buf.data(), to_read);
            size_t bytes_read_this_iteration = in_s.gcount();

            if (bytes_read_this_iteration == 0 && in_s.eof() && total_compressed_read < compressed_size_to_read) {
                throw std::runtime_error("LZ4F_decompress: Premature EOF in compressed stream.");
            }
            if (bytes_read_this_iteration == 0) break;
            total_compressed_read += bytes_read_this_iteration;

            const char* src_ptr = in_buf.data();
            size_t src_remaining = bytes_read_this_iteration;
            while (src_remaining > 0) {
                size_t dst_capacity = out_buf.size();
                size_t src_chunk_processed = src_remaining;
                size_t decompressed_size =
                    LZ4F_decompress(dctx.get(), out_buf.data(), &dst_capacity, src_ptr, &src_chunk_processed, nullptr);
                if (LZ4F_isError(decompressed_size))
                    throw std::runtime_error("LZ4 decompression failed: " +
                                             std::string(LZ4F_getErrorName(decompressed_size)));
                out_s.write(out_buf.data(), dst_capacity);
                total_original_size += dst_capacity;
                src_ptr += src_chunk_processed;
                src_remaining -= src_chunk_processed;
                if (decompressed_size == 0) {
                    end_of_frame = true;
                    break;
                }
            }
            if (in_s.fail() && !in_s.eof()) throw std::runtime_error("Error reading compressed data from archive.");
        }
        return total_original_size;
    }

    void read_directory() {
        directory.clear();
        if (!fs::exists(archive_path) || fs::file_size(archive_path) < (MAGIC_LEN + DIRECTORY_SIZE_LEN)) return;

        std::ifstream file(archive_path, std::ios::binary);
        if (!file) throw std::runtime_error("Cannot open archive file: " + archive_path);

        file.seekg(-(MAGIC_LEN + DIRECTORY_SIZE_LEN), std::ios::end);
        uint64_t directory_block_size = read_uint64_le(file);

        uint64_t file_sz = fs::file_size(archive_path);
        if (file_sz < (MAGIC_LEN + DIRECTORY_SIZE_LEN + directory_block_size)) {
            throw std::runtime_error("Archive directory size mismatch or file too small.");
        }

        uint64_t dir_actual_start_pos = file_sz - (MAGIC_LEN + DIRECTORY_SIZE_LEN + directory_block_size);

        char magic_check[MAGIC_LEN];
        file.seekg(-MAGIC_LEN, std::ios::end);
        file.read(magic_check, MAGIC_LEN);
        if (file.gcount() != MAGIC_LEN || std::memcmp(magic_check, MAGIC, MAGIC_LEN) != 0) {
            throw std::runtime_error("Invalid archive format or magic number mismatch.");
        }

        file.seekg(dir_actual_start_pos);

        uint64_t bytes_parsed_from_dir_block = 0;
        std::vector<char> filename_buffer;

        while (bytes_parsed_from_dir_block < directory_block_size) {
            if (file.eof() || file.fail()) {
                throw std::runtime_error("Unexpected EOF or read error while parsing directory entries.");
            }

            uint32_t filename_len = read_uint32_le(file);
            bytes_parsed_from_dir_block += 4;

            std::string filename_str;
            if (filename_len > 0) {
                if (filename_len > 10 * 1024 * 1024) {
                    throw std::runtime_error("Excessively long filename in directory: " + std::to_string(filename_len));
                }
                filename_buffer.resize(filename_len);
                file.read(filename_buffer.data(), filename_len);
                if (static_cast<uint32_t>(file.gcount()) != filename_len)
                    throw std::runtime_error("Failed to read full filename in directory");
                filename_str.assign(filename_buffer.data(), filename_len);
            }
            bytes_parsed_from_dir_block += filename_len;

            uint64_t offset = read_uint64_le(file);
            uint64_t compressed_size = read_uint64_le(file);
            uint64_t original_size = read_uint64_le(file);
            bytes_parsed_from_dir_block += 24;

            directory[filename_str] = FileEntry(offset, compressed_size, original_size);

            if (bytes_parsed_from_dir_block > directory_block_size) {
                throw std::runtime_error("Directory parsing read beyond expected size.");
            }
        }
        if (bytes_parsed_from_dir_block != directory_block_size && directory_block_size != 0) {
            throw std::runtime_error(
                "Directory parsing did not consume entire directory block. "
                "Expected: " +
                std::to_string(directory_block_size) + " Got: " + std::to_string(bytes_parsed_from_dir_block));
        }
    }

    void write_directory_to_stream(std::ostream& out_s) {
        uint64_t estimated_serialized_size = 0;
        for (const auto& [filename, entry] : directory) {
            estimated_serialized_size += 4 + filename.length() + 24;
        }

        if (estimated_serialized_size < MAX_DIR_SERIALIZED_IN_MEMORY || directory.empty()) {
            // fast path for smaller directories
            std::vector<char> serialized_dir_data_temp_buf;
            if (!directory.empty()) serialized_dir_data_temp_buf.reserve(estimated_serialized_size);

            for (const auto& [filename, entry] : directory) {
                uint32_t filename_len = filename.length();
                char len_bytes[4];
                len_bytes[0] = filename_len & 0xFF;
                len_bytes[1] = (filename_len >> 8) & 0xFF;
                len_bytes[2] = (filename_len >> 16) & 0xFF;
                len_bytes[3] = (filename_len >> 24) & 0xFF;
                serialized_dir_data_temp_buf.insert(serialized_dir_data_temp_buf.end(), len_bytes, len_bytes + 4);
                serialized_dir_data_temp_buf.insert(serialized_dir_data_temp_buf.end(), filename.begin(),
                                                    filename.end());

                char entry_bytes[24];
                uint64_t values[] = {entry.offset, entry.compressed_size, entry.original_size};
                for (int val_idx = 0; val_idx < 3; ++val_idx) {
                    uint64_t val = values[val_idx];
                    for (int i = 0; i < 8; i++) entry_bytes[val_idx * 8 + i] = (val >> (i * 8)) & 0xFF;
                }
                serialized_dir_data_temp_buf.insert(serialized_dir_data_temp_buf.end(), entry_bytes, entry_bytes + 24);
            }
            out_s.write(serialized_dir_data_temp_buf.data(), serialized_dir_data_temp_buf.size());
            write_uint64_le(out_s, serialized_dir_data_temp_buf.size());
        } else {
            TemporaryDirectory temp_dir_manager;
            fs::path temp_dir_file_path =
                temp_dir_manager.path() /
                ("archivedir_" +
                 std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                    std::chrono::high_resolution_clock::now().time_since_epoch())
                                    .count()) +
                 ".tmp");

            std::ofstream temp_dir_os(temp_dir_file_path, std::ios::binary | std::ios::trunc);
            if (!temp_dir_os)
                throw std::runtime_error("Failed to create temporary file for large directory: " +
                                         temp_dir_file_path.string());

            uint64_t actual_dir_data_size_streamed = 0;
            for (const auto& [filename, entry] : directory) {
                write_uint32_le(temp_dir_os, filename.length());
                temp_dir_os.write(filename.data(), filename.length());
                write_uint64_le(temp_dir_os, entry.offset);
                write_uint64_le(temp_dir_os, entry.compressed_size);
                write_uint64_le(temp_dir_os, entry.original_size);
                actual_dir_data_size_streamed += (4 + filename.length() + 24);
            }
            temp_dir_os.close();

            std::ifstream temp_dir_is(temp_dir_file_path, std::ios::binary);
            if (!temp_dir_is)
                throw std::runtime_error("Failed to open temporary directory file for reading: " +
                                         temp_dir_file_path.string());

            std::vector<char> copy_buf(STREAM_BUFFER_SIZE);
            while (temp_dir_is) {
                temp_dir_is.read(copy_buf.data(), copy_buf.size());
                std::streamsize n = temp_dir_is.gcount();
                if (n > 0)
                    out_s.write(copy_buf.data(), n);
                else if (temp_dir_is.eof())
                    break;
                else if (temp_dir_is.fail())
                    throw std::runtime_error("Error reading from temporary directory file.");
            }
            temp_dir_is.close();
            write_uint64_le(out_s, actual_dir_data_size_streamed);
        }
        out_s.write(MAGIC, MAGIC_LEN);
    }

    uint64_t get_data_append_offset() {
        if (!fs::exists(archive_path) || fs::file_size(archive_path) == 0) return 0;
        std::ifstream temp_read(archive_path, std::ios::binary);
        if (!temp_read) return 0;
        temp_read.seekg(0, std::ios::end);
        uint64_t total_file_size = temp_read.tellg();
        if (total_file_size < (MAGIC_LEN + DIRECTORY_SIZE_LEN)) return 0;
        temp_read.seekg(-(MAGIC_LEN + DIRECTORY_SIZE_LEN), std::ios::end);
        uint64_t dir_block_size = read_uint64_le(temp_read);
        if (total_file_size < (MAGIC_LEN + DIRECTORY_SIZE_LEN + dir_block_size)) return 0;
        return total_file_size - (MAGIC_LEN + DIRECTORY_SIZE_LEN + dir_block_size);
    }

   public:
    explicit LZ4Archive(const std::string& path) : archive_path(path) {
        unsigned int num_hw_threads = std::thread::hardware_concurrency();
        pool = std::make_unique<ThreadPool>(num_hw_threads > 0 ? num_hw_threads : 2);
    }

    // Progress reporting helper
    void print_progress(const std::string& operation, size_t current, size_t total,
                        const std::string& current_file = "") {
        int bar_width = 30;
        float progress = (total == 0) ? 0.0f : (float)current / total;
        int pos = bar_width * progress;

        std::cout << operation << " [";
        for (int i = 0; i < bar_width; ++i) {
            if (i < pos)
                std::cout << "=";
            else if (i == pos)
                std::cout << ">";
            else
                std::cout << " ";
        }
        std::cout << "] " << int(progress * 100.0) << " % (" << current << "/" << total << ")";
        if (!current_file.empty() && current_file.length() < 40) {  // Limit filename display length
            std::cout << " - " << current_file.substr(0, 39);
        } else if (!current_file.empty()) {
            std::cout << " - ..." << current_file.substr(current_file.length() - 35, 35);
        }
        std::cout << "\r";
        std::cout.flush();
        if (current == total) std::cout << std::endl;
    }

    void add_file(const std::string& file_path, const std::string& archive_name_override = "") {
        std::string name_in_archive =
            archive_name_override.empty() ? fs::path(file_path).filename().string() : archive_name_override;
        if (!fs::exists(file_path) || !fs::is_regular_file(file_path)) {
            throw std::runtime_error("File not found or not a regular file: " + file_path);
        }
        uint64_t original_file_size = fs::file_size(file_path);
        read_directory();

        std::ifstream input_file_stream(file_path, std::ios::binary);
        if (!input_file_stream) throw std::runtime_error("Cannot open input file: " + file_path);

        uint64_t data_append_offset = get_data_append_offset();
        std::fstream archive_fs(archive_path, std::ios::binary | std::ios::in | std::ios::out | std::ios::app);
        if (!archive_fs.is_open()) {
            archive_fs.open(archive_path, std::ios::binary | std::ios::out | std::ios::trunc);
            if (!archive_fs.is_open()) throw std::runtime_error("Cannot open/create archive file: " + archive_path);
            data_append_offset = 0;
        }

        archive_fs.seekp(data_append_offset);
        uint64_t new_file_data_offset = archive_fs.tellp();
        uint64_t compressed_s = compress_stream_to_stream(input_file_stream, archive_fs, original_file_size);

        directory[name_in_archive] = FileEntry(new_file_data_offset, compressed_s, original_file_size);
        write_directory_to_stream(archive_fs);
        uint64_t final_archive_size = archive_fs.tellp();
        archive_fs.close();
        fs::resize_file(archive_path, final_archive_size);

        std::cout << "Added (stream): " << name_in_archive << " (" << original_file_size << " -> " << compressed_s
                  << " bytes)\n";
    }

    struct ParallelCompressionResult {
        std::string archive_name;
        std::string temp_compressed_path;
        uint64_t compressed_size_on_disk;
        uint64_t original_size;
        bool success;
        std::string error_message;
        std::string source_file_path;
    };

    static ParallelCompressionResult compress_file_to_temp_task(const std::string& file_to_compress_path,
                                                                const std::string& name_in_archive,
                                                                const fs::path& temp_storage_dir_path) {
        fs::path temp_file_path =
            temp_storage_dir_path / (fs::path(name_in_archive).filename().string() + "_" +
                                     std::to_string(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                        std::chrono::high_resolution_clock::now().time_since_epoch())
                                                        .count()) +
                                     ".lz4tmp");

        uint64_t original_s = 0;
        uint64_t compressed_s = 0;
        ParallelCompressionResult result;

        try {
            original_s = fs::file_size(file_to_compress_path);
            std::ifstream input_s(file_to_compress_path, std::ios::binary);
            if (!input_s) {
                result = {name_in_archive, "", 0, original_s, false, "Cannot open source file", file_to_compress_path};
            } else {
                std::ofstream temp_output_s(temp_file_path, std::ios::binary | std::ios::trunc);
                if (!temp_output_s) {
                    result = {name_in_archive,      "", 0, original_s, false, "Cannot create temporary compressed file",
                              file_to_compress_path};
                } else {
                    compressed_s = compress_stream_to_stream(input_s, temp_output_s, original_s);
                    temp_output_s.close();
                    if (temp_output_s.fail()) {
                        fs::remove(temp_file_path);
                        result = {name_in_archive,      "",    0,
                                  original_s,           false, "Failed to write all data to temporary compressed file",
                                  file_to_compress_path};
                    } else {
                        result = {name_in_archive,      temp_file_path.string(), compressed_s, original_s, true, "",
                                  file_to_compress_path};
                    }
                }
            }
        } catch (const std::exception& e) {
            if (fs::exists(temp_file_path)) fs::remove(temp_file_path);
            result = {name_in_archive, "", 0, original_s, false, e.what(), file_to_compress_path};
        }

        return result;
    }

    void add_files_batch(const std::vector<std::string>& source_paths_or_dirs, std::string& root_dir_str) {
        if (source_paths_or_dirs.empty()) return;
        read_directory();

        TemporaryDirectory temp_files_manager;

        std::vector<std::pair<std::string, std::string>> files_to_process;  // {full_path, name_in_archive}
        for (const auto& path_str : source_paths_or_dirs) {
            fs::path current_fs_path(path_str);
            if (!fs::exists(current_fs_path)) {
                std::cerr << "Warning: Path does not exist, skipping: " << path_str << "\n";
                continue;
            }
            if (fs::is_regular_file(current_fs_path)) {
                std::string rel_path_str = fs::relative(current_fs_path.string(), root_dir_str).lexically_normal().string();
                files_to_process.emplace_back(current_fs_path.string(), rel_path_str);
            } else if (fs::is_directory(current_fs_path)) {
                for (const auto& dir_entry : fs::recursive_directory_iterator(current_fs_path)) {
                    if (dir_entry.is_regular_file()) {
                        std::string rel_path_str = fs::relative(dir_entry.path(), root_dir_str).lexically_normal().string();
#ifdef _WIN32
                        std::replace(rel_path_str.begin(), rel_path_str.end(), '\\', '/');
#endif
                        files_to_process.emplace_back(dir_entry.path().string(), rel_path_str);
                    }
                }
            }
        }
        if (files_to_process.empty()) {
            std::cout << "No files found to add.\n";
            return;
        }

        std::vector<std::future<ParallelCompressionResult>> compression_futures;
        size_t total_to_compress = files_to_process.size();
        std::cout << "Starting compression for " << total_to_compress << " files...\n";

        for (const auto& [file_full_path, name_in_archive] : files_to_process) {
            compression_futures.push_back(pool->enqueue(compress_file_to_temp_task, file_full_path, name_in_archive,
                                                        temp_files_manager.path()));
        }

        std::vector<ParallelCompressionResult> results;
        uint64_t total_original_s = 0, total_compressed_s = 0;
        size_t success_count = 0;
        size_t futures_processed = 0;

        // Retrieve results and update progress
        for (auto& fut : compression_futures) {
            ParallelCompressionResult item = fut.get();
            results.push_back(std::move(item));
            futures_processed++;
            print_progress("Compressing", futures_processed, total_to_compress, item.source_file_path);

            if (item.success) {
                total_original_s += item.original_size;
                total_compressed_s += item.compressed_size_on_disk;
                success_count++;
            } else {
                std::cerr << "\nWarning: Failed to compress " << item.source_file_path << " (as " << item.archive_name
                          << "): " << item.error_message << "\n";
            }
        }
        std::cout << std::endl;

        if (success_count == 0) {
            std::cout << "No files were successfully compressed to add.\n";
            return;
        }

        uint64_t data_append_offset = get_data_append_offset();
        std::fstream archive_fs;
        if (fs::exists(archive_path) && fs::file_size(archive_path) > 0) {
            archive_fs.open(archive_path, std::ios::binary | std::ios::in | std::ios::out);
            data_append_offset = get_data_append_offset();
        } else {
            archive_fs.open(archive_path, std::ios::binary | std::ios::out | std::ios::trunc);
            data_append_offset = 0;
        }
        if (!archive_fs.is_open()) {
            throw std::runtime_error("Cannot open/create archive file: " + archive_path);
        }
        archive_fs.seekp(data_append_offset);
        std::vector<char> copy_buffer(STREAM_BUFFER_SIZE);

        size_t write_progress_count = 0;
        std::cout << "Writing " << success_count << " compressed files to archive...\n";
        for (const auto& item : results) {
            if (!item.success) continue;
            write_progress_count++;
            print_progress("Writing", write_progress_count, success_count, item.archive_name);

            uint64_t current_file_offset_in_archive = archive_fs.tellp();
            std::ifstream temp_in(item.temp_compressed_path, std::ios::binary);
            if (!temp_in) {
                std::cerr << "\nError: Could not open temporary compressed file " << item.temp_compressed_path
                          << " for reading. Skipping.\n";
                continue;
            }

            while (temp_in) {
                temp_in.read(copy_buffer.data(), copy_buffer.size());
                std::streamsize n = temp_in.gcount();
                if (n > 0)
                    archive_fs.write(copy_buffer.data(), n);
                else if (temp_in.eof())
                    break;
                else if (temp_in.fail()) {
                    temp_in.close();
                    throw std::runtime_error("Error reading from temp file: " + item.temp_compressed_path);
                }
            }
            temp_in.close();
            directory[item.archive_name] =
                FileEntry(current_file_offset_in_archive, item.compressed_size_on_disk, item.original_size);
        }
        std::cout << std::endl;

        write_directory_to_stream(archive_fs);
        uint64_t final_archive_size = archive_fs.tellp();
        archive_fs.close();
        fs::resize_file(archive_path, final_archive_size);

        double ratio = total_original_s > 0 ? (1.0 - (double)total_compressed_s / total_original_s) * 100.0 : 0.0;
        std::cout << "Batch Add Summary: " << success_count << "/" << total_to_compress
                  << " files added successfully.\n"
                  << "Total Original: " << total_original_s << " bytes, Total Compressed: " << total_compressed_s
                  << " bytes (" << std::fixed << std::setprecision(1) << ratio << "% compression)\n";
    }

    void extract_file(const std::string& archive_name, const std::string& output_path_override = "") {
        read_directory();
        auto it = directory.find(archive_name);
        if (it == directory.end()) throw std::runtime_error("File not found in archive: " + archive_name);

        const auto& entry = it->second;
        std::string out_file_actual_path = output_path_override.empty() ? archive_name : output_path_override;

        fs::path out_fs_path(out_file_actual_path);
        if (out_fs_path.has_parent_path() && !out_fs_path.parent_path().empty()) {
            fs::create_directories(out_fs_path.parent_path());
        }

        std::ifstream archive_ifs(archive_path, std::ios::binary);
        if (!archive_ifs) throw std::runtime_error("Cannot open archive: " + archive_path);
        archive_ifs.seekg(entry.offset);

        std::ofstream output_ofs(out_file_actual_path, std::ios::binary | std::ios::trunc);
        if (!output_ofs) throw std::runtime_error("Cannot create output file: " + out_file_actual_path);

        uint64_t actual_decompressed_size = decompress_stream_data(archive_ifs, output_ofs, entry.compressed_size);
        output_ofs.close();

        if (entry.original_size != 0 && actual_decompressed_size != entry.original_size) {
            // Suppress for batch, or make it optional.
            // std::cerr << "Warning: Decompressed size (" << actual_decompressed_size
            //           << ") for " << archive_name << " does not match record (" <<
            //           entry.original_size << ").\n";
        }

        std::cout << "Extracted (stream): " << archive_name << " -> " << out_file_actual_path << " ("
                    << (entry.original_size ? entry.original_size : actual_decompressed_size) << " bytes)\n";
    }

    void extract_all(const std::string& output_dir_base = ".") {
        read_directory();
        if (directory.empty()) {
            std::cout << "Archive is empty or not found.\n";
            return;
        }

        std::vector<std::string> filenames_to_extract;
        filenames_to_extract.reserve(directory.size());
        for (const auto& [filename, entry] : directory) {
            filenames_to_extract.push_back(filename);
        }

        fs::path base_output_fs_path(output_dir_base);
        if (!fs::exists(base_output_fs_path)) fs::create_directories(base_output_fs_path);

        size_t total_to_extract = filenames_to_extract.size();
        size_t extracted_count = 0;
        std::cout << "Extracting " << total_to_extract << " files to " << base_output_fs_path.string() << "...\n";

        for (const auto& filename_in_archive : filenames_to_extract) {
            extracted_count++;
            print_progress("Extracting", extracted_count, total_to_extract, filename_in_archive);
            try {
                fs::path final_output_path = base_output_fs_path / filename_in_archive;
                extract_file(filename_in_archive, final_output_path.string());
            } catch (const std::exception& e) {
                std::cerr << "\nError extracting " << filename_in_archive << ": " << e.what() << "\n";
            }
        }
        std::cout << std::endl;  // Final newline for progress bar
        std::cout << "Extraction complete. " << extracted_count << "/" << total_to_extract << " files processed.\n";
    }

    void list_files() {
        read_directory();
        if (directory.empty()) {
            std::cout << "Archive is empty or does not exist.\n";
            return;
        }

        std::cout << std::left << std::setw(40) << "Filename" << std::right << std::setw(12) << "Original"
                  << std::setw(12) << "Compressed" << std::setw(8) << "Ratio" << "\n";
        std::cout << std::string(112, '-') << "\n";

        uint64_t total_orig = 0, total_comp = 0;
        for (const auto& [name, entry] : directory) {
            double ratio_val =
                entry.original_size > 0 ? (1.0 - (double)entry.compressed_size / entry.original_size) * 100.0 : 0.0;
            std::cout << std::left << std::setw(80) << name.substr(0, 79) << std::right << std::setw(12)
                      << entry.original_size << std::setw(12) << entry.compressed_size << std::setw(7) << std::fixed
                      << std::setprecision(1) << ratio_val << "%\n";
            total_orig += entry.original_size;
            total_comp += entry.compressed_size;
        }

        if (directory.size() > 1) {
            double total_ratio_val = total_orig > 0 ? (1.0 - (double)total_comp / total_orig) * 100.0 : 0.0;
            std::cout << std::string(112, '-') << "\n";
            std::cout << std::left << std::setw(80) << "TOTAL (" + std::to_string(directory.size()) + " files)"
                      << std::right << std::setw(12) << total_orig << std::setw(12) << total_comp << std::setw(7)
                      << std::fixed << std::setprecision(1) << total_ratio_val << "%\n";
        }
    }
};

uint64_t compress_stream_to_stream(std::istream& in_s, std::ostream& out_s, uint64_t original_size_hint) {
    LZ4FCompressionContext cctx;
    LZ4F_preferences_t prefs = {};
    prefs.frameInfo.contentSize = original_size_hint;
    // prefs.compressionLevel = LZ4F_CLEVEL_DEFAULT;

    std::vector<char> in_buf(LZ4Archive::STREAM_BUFFER_SIZE);
    std::vector<char> out_buf(LZ4F_compressBound(in_buf.size(), &prefs));
    uint64_t total_compressed_size = 0;

    size_t header_size = LZ4F_compressBegin(cctx.get(), out_buf.data(), out_buf.size(), &prefs);
    if (LZ4F_isError(header_size))
        throw std::runtime_error("LZ4F_compressBegin failed: " + std::string(LZ4F_getErrorName(header_size)));
    out_s.write(out_buf.data(), header_size);
    total_compressed_size += header_size;

    while (in_s) {
        in_s.read(in_buf.data(), in_buf.size());
        size_t bytes_read = in_s.gcount();
        if (bytes_read == 0) break;

        size_t compressed_chunk_size =
            LZ4F_compressUpdate(cctx.get(), out_buf.data(), out_buf.size(), in_buf.data(), bytes_read, nullptr);
        if (LZ4F_isError(compressed_chunk_size))
            throw std::runtime_error("LZ4F_compressUpdate failed: " +
                                     std::string(LZ4F_getErrorName(compressed_chunk_size)));
        out_s.write(out_buf.data(), compressed_chunk_size);
        total_compressed_size += compressed_chunk_size;
    }
    if (in_s.bad()) throw std::runtime_error("Error reading from input stream during compression.");

    size_t end_size = LZ4F_compressEnd(cctx.get(), out_buf.data(), out_buf.size(), nullptr);
    if (LZ4F_isError(end_size))
        throw std::runtime_error("LZ4F_compressEnd failed: " + std::string(LZ4F_getErrorName(end_size)));
    out_s.write(out_buf.data(), end_size);
    total_compressed_size += end_size;

    if (out_s.fail()) throw std::runtime_error("Error writing to output stream during compression.");
    return total_compressed_size;
}

void show_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <archive> <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  add <files_or_dirs...> Add file(s) or directories to archive.\n";
    std::cout << "                         Uses thread pool for batch compression.\n";
    std::cout << "  extract [files...]     Extract file(s) from archive (all if "
                 "no files specified).\n";
    std::cout << "                         Uses streaming decompression.\n";
    std::cout << "  list                   List files in archive\n\n";
    std::cout << "Options:\n";
    std::cout << "  -o <dir>               Output directory for extraction.\n";
    std::cout << "  -r <base>              Store added file paths relative to <base>.\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " archive.lz4a add file1.txt path/to/folder/\n";
    std::cout << "  " << program_name << " archive.lz4a add -r /a/b /a/b/c/file1.txt\n";
    std::cout << "                         (adds as c/file1.txt in archive)\n";
    std::cout << "  " << program_name << " archive.lz4a list\n";
    std::cout << "  " << program_name << " archive.lz4a extract -o output_dir/\n";
    std::cout << "  " << program_name
              << " archive.lz4a extract file1.txt path/in/archive/file.txt -o "
                 "output_dir/\n";
}

int main(int argc, char* argv[]) {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    if (argc < 3) {
        show_usage(argv[0]);
        return 1;
    }

    std::string archive_path_main = argv[1];
    std::string command_main = argv[2];

    try {
        LZ4Archive archive(archive_path_main);

        if (command_main == "add") {
            if (argc < 4) {
                std::cerr << "Error: No files or directories specified for add command.\n";
                show_usage(argv[0]);
                return 1;
            }
            std::string root_dir_str = "/";
            std::vector<std::string> paths_to_add;
            for (int i = 3; i < argc; i++) {
                if (std::string(argv[i]) == "-r" && i + 1 < argc) {
                    root_dir_str = argv[++i];
                } else {
                    paths_to_add.push_back(argv[i]);
                }
            }

            // Use batch for multiple items or single directory, direct add for single
            // file
            // if (paths_to_add.size() == 1 && fs::is_regular_file(paths_to_add[0])) {
            //     archive.add_file(paths_to_add[0]);
            // } else {
            archive.add_files_batch(paths_to_add, root_dir_str);
            // }
        } else if (command_main == "extract") {
            std::string output_dir_str = ".";
            std::vector<std::string> files_to_extract;

            for (int i = 3; i < argc; i++) {
                if (std::string(argv[i]) == "-o" && i + 1 < argc) {
                    output_dir_str = argv[++i];
                } else {
                    files_to_extract.push_back(argv[i]);
                }
            }

            if (files_to_extract.empty()) {
                archive.extract_all(output_dir_str);
            } else {
                size_t total_files = files_to_extract.size();
                size_t current_file_idx = 0;
                if (total_files > 1) std::cout << "Extracting " << total_files << " specified files...\n";

                for (const auto& file_in_archive : files_to_extract) {
                    current_file_idx++;
                    if (total_files > 1) {  // Only show progress bar for multiple specified files
                        archive.print_progress("Extracting", current_file_idx, total_files, file_in_archive);
                    }
                    std::string final_output_path_str;
                    if (output_dir_str == ".") {
                        final_output_path_str = file_in_archive;
                    } else {
                        final_output_path_str = (fs::path(output_dir_str) / file_in_archive).string();
                    }
                    try {
                        archive.extract_file(file_in_archive, final_output_path_str);
                    } catch (const std::exception& e) {
                        if (total_files > 1) std::cout << std::endl;
                        std::cerr << "Error extracting " << file_in_archive << ": " << e.what() << "\n";
                    }
                }
                if (total_files > 1) std::cout << std::endl;
            }
        } else if (command_main == "list") {
            archive.list_files();
        } else {
            std::cerr << "Error: Unknown command '" << command_main << "'\n";
            show_usage(argv[0]);
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
