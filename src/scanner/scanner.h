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

    // "MALICIOUS"  : SHA-256 is in the blocklist
    // "SUSPICIOUS" : static PE heuristics scored high and the file is not
    //                validly signed (see heuristicScore / details)
    // "CLEAN", "ERROR", "SKIPPED" (cloud placeholder, device, too large)
    std::string verdict;

    int heuristicScore = 0;   // 0 for non-PE files and cache hits
    std::string details;      // human-readable reasons for SUSPICIOUS

    // Windows error code when verdict == "ERROR" (0 if not applicable).
    unsigned long winError = 0;
};

class HashDetector;

// Detection pipeline per file:
//   1. scan cache (unchanged clean file -> only the hash is looked up again)
//   2. SHA-256 blocklist                     -> MALICIOUS
//   3. static PE analysis (packers, injection APIs, ransom/credential
//      strings, ...)                          -> score
//   4. score >= threshold and no valid Authenticode / catalog signature
//                                             -> SUSPICIOUS
//
// Not thread-safe: use one Scanner per thread.
class Scanner
{
public:
    // Bump when heuristics change: invalidates the on-disk scan cache.
    static constexpr std::uint32_t kEngineVersion = 1;

    // Files above this size are skipped (keeps full scans light).
    static constexpr std::uint64_t kMaxFileSize = 256ull * 1024 * 1024;

    // PE files up to this size are kept in memory for heuristic analysis.
    static constexpr std::uint64_t kMaxAnalyzeSize = 32ull * 1024 * 1024;

    Scanner();
    ~Scanner();

    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;

    // Opens the crypto provider, loads the hash database and (optionally)
    // the scan cache. Returns false if the database is missing or empty.
    [[nodiscard]] bool initialize(
        const std::filesystem::path& databasePath,
        const std::filesystem::path& cachePath = {});

    [[nodiscard]] ScanResult scan(const std::filesystem::path& filePath);

    // Persists the scan cache (no-op when unchanged or not configured).
    void saveCache();

    [[nodiscard]] std::size_t databaseSize() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::unique_ptr<HashDetector> detector_;
};
