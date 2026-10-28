#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <unordered_map>

namespace blade
{
    // Remembers files that were already scanned and found clean, so a repeat
    // scan skips reading them. An entry is only trusted while the file's size
    // and last-write time are unchanged. The SHA-256 is stored too, so when the
    // hash database is updated the cached hash is simply looked up again in the
    // new database: no file has to be re-read for that.
    //
    // Known trade-off (same as other AV caches): an attacker who can forge the
    // last-write time AND keep the size identical can reuse a stale entry.
    //
    // Not thread-safe.
    class ScanCache
    {
    public:
        using Digest = std::array<std::uint8_t, 32>;

        static constexpr std::size_t kMaxEntries = 500000;

        // Loads the cache file. If it is missing, damaged, or was written by a
        // different engine version, the cache starts empty. Returns the number
        // of entries loaded.
        std::size_t load(const std::filesystem::path& file,
                         std::uint32_t engineVersion);

        bool find(const std::filesystem::path& path, std::uint64_t size,
                  std::uint64_t mtime, Digest& sha256) const;

        void add(const std::filesystem::path& path, std::uint64_t size,
                 std::uint64_t mtime, const Digest& sha256);

        // Atomic (temp file + rename). Entries that were never used in this
        // session are dropped first when the cache is nearly full.
        bool save(const std::filesystem::path& file,
                  std::uint32_t engineVersion);

        void clear();
        std::size_t size() const { return map_.size(); }
        bool dirty() const { return dirty_; }

    private:
        struct Entry
        {
            std::uint64_t size = 0;
            std::uint64_t mtime = 0;
            Digest sha256{};
            mutable bool touched = false; // memory only
        };

        static std::uint64_t keyOf(const std::filesystem::path& path);

        std::unordered_map<std::uint64_t, Entry> map_;
        bool dirty_ = false;
    };
}
