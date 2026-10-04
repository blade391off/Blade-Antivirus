#pragma once

#include <string>
#include <unordered_set>

class HashDetector {
public:
    bool loadDatabase(const std::string& path);
    bool contains(const std::string& sha256) const;
    size_t size() const;

private:
    std::unordered_set<std::string> hashes;
};