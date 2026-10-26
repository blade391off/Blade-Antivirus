#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

struct ScanResult
{
    std::wstring file;
    std::string sha256;

    bool hashMatch = false;
    bool isPE = false;

    // "MALICIOUS", "CLEAN", "ERROR" or "SKIPPED".
    // SKIPPED = cloud-only placeholder, device/pipe, or above kMaxFileSize.
    std::string verdict;

    // Windows error code when verdict == "ERROR" (0 if not applicable),
    // e.g. 5 = access denied, 32 = sharing violation.
    unsigned long winError = 0;
};

class HashDetector;

// Not thread-safe: use one Scanner per thread.
class Scanner
{
public:
    // Files above this size are skipped (keeps full scans light).
    static constexpr std::uint64_t kMaxFileSize = 256ull * 1024 * 1024;

    Scanner();
    ~Scanner();

    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;

    // Opens the crypto provider once and loads the hash database.
    // Returns false if the database is missing, unreadable or empty.
    [[nodiscard]] bool initialize(const std::filesystem::path& databasePath);

    [[nodiscard]] ScanResult scan(const std::filesystem::path& filePath);

    [[nodiscard]] std::size_t databaseSize() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::unique_ptr<HashDetector> detector_;
};
