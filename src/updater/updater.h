#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <vector>

class Updater
{
public:
    // Default: romainmarcoux/malicious-hash (MIT), updated hourly.
    static std::vector<std::string> defaultSources();

   
    static std::vector<std::string> loadSources(
        const std::filesystem::path& configPath);

    bool updateHashes(
        const std::filesystem::path& hashesPath,
        const std::filesystem::path& statePath,
        const std::vector<std::string>& sources,
        std::string& status,
        bool force = false,
        std::function<void(const std::string&)> progressCallback = {}
    );

private:
    enum class FetchStatus { Ok, NotModified, NotFound, Error };

   
    FetchStatus httpGet(
        const std::string& url,
        const std::string& etag,
        std::string& response,
        std::string& newEtag,
        std::string& error
    );
};
