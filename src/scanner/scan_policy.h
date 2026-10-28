#pragma once

#include <filesystem>

namespace blade
{
    // Real-time protection only looks at file types that can carry code or
    // be executed/opened to run code (programs, scripts, installers, shortcuts,
    // macro documents, archives). Everything else (photos, text, video ...)
    // is ignored, which keeps the background load near zero.
    bool hasScannableExtension(const std::filesystem::path& path);

    // True if `path` is `dir` itself or lies inside it
    // (ASCII case-insensitive, '/' and '\' are equivalent).
    bool isInsideDirectory(const std::filesystem::path& path,
                           const std::filesystem::path& dir);
}
