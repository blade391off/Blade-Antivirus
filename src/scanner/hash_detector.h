#pragma once

#include <array>
#include <cstddef>
#include <filesystem>
#include <string>
#include <unordered_set>

class HashDetector {
public:
    using Digest = std::array<unsigned char, 32>;

    bool loadDatabase(const std::string& path);
    bool loadDatabase(const std::filesystem::path& path);

    bool contains(const std::string& sha256) const;
    bool contains(const Digest& digest) const;

    std::size_t size() const;

private:
    std::unordered_set<std::string> hashes;
};