#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace blade
{
    // Collects "this file changed" events and releases a file only after it has
    // been quiet for `settle`. Files are written in many small steps, so
    // scanning on the first event would read half-written data.
    //
    // Also handles busy files (retry with back-off) and bounds memory: when
    // `maxEntries` paths are already waiting, new ones are dropped and counted.
    //
    // Paths are compared ASCII-case-insensitively (Windows semantics).
    // Not thread-safe: the caller locks.
    class PendingQueue
    {
    public:
        using Clock = std::chrono::steady_clock;
        using Millis = std::chrono::milliseconds;

        explicit PendingQueue(Millis settle = Millis(1500),
                              std::size_t maxEntries = 5000,
                              int maxRetries = 5);

        // A new event for `path`: (re)starts its quiet period.
        void touch(const std::filesystem::path& path, Clock::time_point now);

        // Removes and returns up to `limit` paths whose quiet period is over.
        // The caller must then call done() or retryLater() for each of them.
        std::vector<std::filesystem::path> takeReady(Clock::time_point now,
                                                     std::size_t limit);

        // Finished with this path (scanned, or gave up): forget retry state.
        void done(const std::filesystem::path& path);

        // The file was busy: queue it again with exponential back-off.
        // Returns false (and forgets the path) once retries are exhausted.
        bool retryLater(const std::filesystem::path& path, Clock::time_point now);

        // When the next waiting path becomes ready; empty if nothing waits.
        std::optional<Clock::time_point> nextReadyTime() const;

        std::size_t size() const { return entries_.size(); }
        std::uint64_t dropped() const { return dropped_; }

    private:
        using Key = std::filesystem::path::string_type;

        struct Entry
        {
            std::filesystem::path path;
            Clock::time_point readyAt;
        };

        static Key keyOf(const std::filesystem::path& path);

        Millis settle_;
        std::size_t maxEntries_;
        int maxRetries_;
        std::uint64_t dropped_ = 0;

        std::unordered_map<Key, Entry> entries_;
        std::unordered_map<Key, int> retries_;
    };
}
