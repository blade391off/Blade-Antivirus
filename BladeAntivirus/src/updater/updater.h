#pragma once

#include <string>

class Updater
{
public:
    bool updateFeeds(
        const std::string& sha256Path,
        const std::string& urlPath,
        const std::string& ipPath,
        const std::string& statePath,
        std::string& status,
        bool force = false
    );

private:
    bool httpGet(
        const std::string& url,
        std::string& response,
        std::string& error
    );

    bool updateFeed(
        const std::string& url,
        const std::string& destination,
        int type,
        size_t& count,
        std::string& error
    );
}; 
