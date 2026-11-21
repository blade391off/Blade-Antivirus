#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace blade
{
    // Real-time protection only looks at file types that can carry code or
    // be executed/opened to run code (programs, scripts, installers, shortcuts,
    // macro documents, archives). Everything else (photos, text, video ...)
    // is ignored, which keeps the background load near zero.
    bool hasScannableExtension(const std::filesystem::path& path);

    // The narrower subset that Windows (or a scripting host) can run
    // directly. The real-time queue handles these before archives and
    // documents, because they are the ones that matter first.
    bool isCodeExtension(const std::filesystem::path& path);

    // True if `path` is `dir` itself or lies inside it
    // (ASCII case-insensitive, '/' and '\' are equivalent).
    bool isInsideDirectory(const std::filesystem::path& path,
                           const std::filesystem::path& dir);

    // True if `path` is inside at least one of `directories`.
    bool isInsideAnyDirectory(
        const std::filesystem::path& path,
        const std::vector<std::filesystem::path>& directories);

    // Real-time scans are capped: a huge archive or installer would keep the
    // single background worker busy for minutes and starve real detections.
    inline constexpr std::uint64_t kRealtimeMaxFileSize =
        32ull * 1024 * 1024;
}
