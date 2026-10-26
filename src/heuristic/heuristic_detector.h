
#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct HeuristicResult
{
    int score = 0;
    bool isPE = false;
    std::vector<std::string> findings;
    std::string error;
};

class HeuristicDetector
{
public:
    static constexpr std::uint64_t MaxFileSize =
        256ull * 1024 * 1024;

    [[nodiscard]]
    HeuristicResult analyze(const std::wstring& filePath) const;
};
