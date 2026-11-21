#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

struct ScanResult
{
    std::wstring file;
    std::string sha256;

    bool hashMatch = false;
    bool isPE = false;
    bool yaraMatch = false;

    std::vector<std::string> yaraMatches;

    std::string verdict;

    int heuristicScore = 0;
    std::string details;

    unsigned long winError = 0;
};

// Per-call limits. Manual scans use the defaults; background (real-time)
// scans pass tighter values so a single huge file cannot stall the queue.
struct ScanLimits
{
    std::uint64_t maxFileSize = 256ull * 1024 * 1024;
    std::uint64_t maxAnalyzeSize = 32ull * 1024 * 1024;
    int yaraTimeoutSeconds = 30;
};

class HashDetector;

class Scanner
{
public:
    static constexpr std::uint32_t kEngineVersion = 2;

    static constexpr std::uint64_t kMaxFileSize =
        256ull * 1024 * 1024;

    static constexpr std::uint64_t kMaxAnalyzeSize =
        32ull * 1024 * 1024;

    Scanner();
    ~Scanner();

    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;

    [[nodiscard]] bool initialize(
        const std::filesystem::path& databasePath,
        const std::filesystem::path& cachePath = {});

    // Why the last initialize() failed; empty after a successful one.
    [[nodiscard]] const std::string& lastError() const;

    // False when the YARA ruleset could not be compiled (detection then
    // falls back to hashes and PE heuristics).
    [[nodiscard]] bool hasYaraRules() const;

    [[nodiscard]] ScanResult scan(
        const std::filesystem::path& filePath);

    [[nodiscard]] ScanResult scan(
        const std::filesystem::path& filePath,
        const ScanLimits& limits);

    void saveCache();

    [[nodiscard]] std::size_t databaseSize() const;

private:
    struct Impl;

    std::unique_ptr<Impl> impl_;
    std::unique_ptr<HashDetector> detector_;

    std::string m_lastError;
};