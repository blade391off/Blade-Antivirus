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

    bool isValidSha256(const std::string& hash)
    {
        if (hash.size() != 64)
            return false;

        return std::all_of(
            hash.begin(),
            hash.end(),
            [](unsigned char c)
            {
                return std::isxdigit(c) != 0;
            }
        );
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
    std::error_code ec;

    if (!std::filesystem::exists(path, ec) || ec)
        return false;

    if (!std::filesystem::is_regular_file(path, ec) || ec)
        return false;

    std::ifstream file(path, std::ios::in);

    if (!file.is_open())
        return false;

    std::unordered_set<std::string> loadedHashes;
    std::string line;

    while (std::getline(file, line))
    {
        line = normalizeHash(std::move(line));

        if (!isValidSha256(line))
            continue;

        loadedHashes.insert(std::move(line));
    }

    if (file.bad())
        return false;

    if (loadedHashes.empty())
        return false;

    hashes = std::move(loadedHashes);

    return true;
}

bool HashDetector::contains(const std::string& sha256) const
{
    const std::string normalized = normalizeHash(sha256);

    if (!isValidSha256(normalized))
        return false;

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