#include "hash_detector.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>

namespace
{
    std::string normalizeHash(std::string value)
    {
        value.erase(
            std::remove_if(
                value.begin(),
                value.end(),
                [](unsigned char c)
                {
                    return std::isspace(c) != 0;
                }
            ),
            value.end()
        );

        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            }
        );

        return value;
    }

    std::string digestToHex(const HashDetector::Digest& digest)
    {
        std::ostringstream stream;
        stream << std::hex << std::setfill('0');

        for (const unsigned char byte : digest)
        {
            stream << std::setw(2)
                << static_cast<unsigned int>(byte);
        }

        return stream.str();
    }
}

bool HashDetector::loadDatabase(const std::string& path)
{
    return loadDatabase(std::filesystem::path(path));
}

bool HashDetector::loadDatabase(const std::filesystem::path& path)
{
    std::ifstream file(path);

    if (!file.is_open())
        return false;

    std::unordered_set<std::string> loadedHashes;
    std::string line;

    while (std::getline(file, line))
    {
        line = normalizeHash(std::move(line));

        if (line.size() != 64)
            continue;

        const bool valid = std::all_of(
            line.begin(),
            line.end(),
            [](unsigned char c)
            {
                return std::isxdigit(c) != 0;
            }
        );

        if (valid)
            loadedHashes.insert(std::move(line));
    }

    if (file.bad())
        return false;

    hashes = std::move(loadedHashes);
    return true;
}

bool HashDetector::contains(const std::string& sha256) const
{
    const std::string normalized = normalizeHash(sha256);

    return hashes.find(normalized) != hashes.end();
}

bool HashDetector::contains(const Digest& digest) const
{
    return contains(digestToHex(digest));
}

std::size_t HashDetector::size() const
{
    return hashes.size();
}