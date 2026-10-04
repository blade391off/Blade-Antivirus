#pragma once

#include <windows.h>
#include <winhttp.h>

#include <string>

struct UpdateInfo
{
    int version = 0;
    std::string url;
    std::string sha256;
    unsigned long long size = 0;
};

class Updater
{
public:
    bool updateDatabase(
        const std::string& manifestUrl,
        const std::string& localDatabase,
        const std::string& localVersionFile,
        std::string& status
    );

    bool check(
        const std::string& versionUrl
    );

    bool download(
        const std::string& url,
        const std::string& destination
    );

private:
    bool parseURL(
        const std::string& url,
        std::wstring& host,
        std::wstring& path,
        INTERNET_PORT& port,
        bool& secure
    );

    bool httpGet(
        const std::wstring& host,
        const std::wstring& path,
        INTERNET_PORT port,
        bool secure,
        std::string& response
    );

    bool calculateSHA256(
        const std::string& filePath,
        std::string& hash
    );

    bool loadLocalVersion(
        const std::string& path,
        int& version
    );

    bool saveLocalVersion(
        const std::string& path,
        int version
    );

    bool parseManifest(
        const std::string& manifest,
        UpdateInfo& info
    );

    bool verifyFile(
        const std::string& path,
        const UpdateInfo& info
    );
};