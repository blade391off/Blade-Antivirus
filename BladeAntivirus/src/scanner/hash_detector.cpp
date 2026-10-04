#include "hash_detector.h"

#include <algorithm>
#include <cctype>
#include <fstream>

bool HashDetector::loadDatabase(const std::string& path)
{
    std::ifstream file(path);

    if (!file.is_open())
        return false;

    hashes.clear();

    std::string line;

    while (std::getline(file, line))
    {
        line.erase(
            std::remove_if(
                line.begin(),
                line.end(),
                [](unsigned char c)
                {
                    return std::isspace(c);
                }
            ),
            line.end()
        );

        if (line.empty())
            continue;

        std::transform(
            line.begin(),
            line.end(),
            line.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            }
        );

        if (line.size() == 64)
            hashes.insert(line);
    }

    return true;
}

bool HashDetector::contains(const std::string& sha256) const
{
    return hashes.find(sha256) != hashes.end();
}

size_t HashDetector::size() const
{
    return hashes.size();
}