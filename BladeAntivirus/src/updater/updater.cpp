#include "updater.h"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace
{
    std::wstring ToWide(
        const std::string& value
    )
    {
        if (value.empty())
            return {};

        int size = MultiByteToWideChar(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            nullptr,
            0
        );

        if (size <= 0)
            return {};

        std::wstring result(
            size,
            L'\0'
        );

        MultiByteToWideChar(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            result.data(),
            size
        );

        return result;
    }

    std::string ToLower(
        std::string value
    )
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(
                    std::tolower(c)
                    );
            }
        );

        return value;
    }

    std::string Trim(
        std::string value
    )
    {
        while (!value.empty() &&
            std::isspace(
                static_cast<unsigned char>(
                    value.front()
                    )
            ))
        {
            value.erase(
                value.begin()
            );
        }

        while (!value.empty() &&
            std::isspace(
                static_cast<unsigned char>(
                    value.back()
                    )
            ))
        {
            value.pop_back();
        }

        return value;
    }

    bool ExtractManifestValue(
        const std::string& manifest,
        const std::string& key,
        std::string& value
    )
    {
        std::istringstream stream(
            manifest
        );

        std::string line;

        while (std::getline(
            stream,
            line
        ))
        {
            line = Trim(line);

            if (line.empty())
                continue;

            const std::size_t separator =
                line.find('=');

            if (separator == std::string::npos)
                continue;

            std::string currentKey =
                Trim(
                    line.substr(
                        0,
                        separator
                    )
                );

            std::string currentValue =
                Trim(
                    line.substr(
                        separator + 1
                    )
                );

            if (currentKey == key)
            {
                value = currentValue;
                return true;
            }
        }

        return false;
    }
}

bool Updater::parseURL(
    const std::string& url,
    std::wstring& host,
    std::wstring& path,
    INTERNET_PORT& port,
    bool& secure
)
{
    std::wstring wideUrl =
        ToWide(url);

    if (wideUrl.empty())
        return false;

    URL_COMPONENTS components{};

    components.dwStructSize =
        sizeof(components);

    wchar_t hostBuffer[256]{};
    wchar_t pathBuffer[8192]{};

    components.lpszHostName =
        hostBuffer;

    components.dwHostNameLength =
        static_cast<DWORD>(
            sizeof(hostBuffer) /
            sizeof(wchar_t)
            );

    components.lpszUrlPath =
        pathBuffer;

    components.dwUrlPathLength =
        static_cast<DWORD>(
            sizeof(pathBuffer) /
            sizeof(wchar_t)
            );

    if (!WinHttpCrackUrl(
        wideUrl.c_str(),
        static_cast<DWORD>(
            wideUrl.length()
            ),
        0,
        &components
    ))
    {
        return false;
    }

    host.assign(
        components.lpszHostName,
        components.dwHostNameLength
    );

    path.assign(
        components.lpszUrlPath,
        components.dwUrlPathLength
    );

    if (components.lpszExtraInfo &&
        components.dwExtraInfoLength > 0)
    {
        path.append(
            components.lpszExtraInfo,
            components.dwExtraInfoLength
        );
    }

    if (path.empty())
        path = L"/";

    port =
        components.nPort;

    secure =
        components.nScheme ==
        INTERNET_SCHEME_HTTPS;

    return true;
}

bool Updater::httpGet(
    const std::wstring& host,
    const std::wstring& path,
    INTERNET_PORT port,
    bool secure,
    std::string& response
)
{
    response.clear();

    HINTERNET session =
        WinHttpOpen(
            L"BladeAntivirus/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0
        );

    if (!session)
        return false;

    WinHttpSetTimeouts(
        session,
        10000,
        10000,
        15000,
        15000
    );

    HINTERNET connection =
        WinHttpConnect(
            session,
            host.c_str(),
            port,
            0
        );

    if (!connection)
    {
        WinHttpCloseHandle(
            session
        );

        return false;
    }

    DWORD flags =
        secure
        ? WINHTTP_FLAG_SECURE
        : 0;

    HINTERNET request =
        WinHttpOpenRequest(
            connection,
            L"GET",
            path.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            flags
        );

    if (!request)
    {
        WinHttpCloseHandle(
            connection
        );

        WinHttpCloseHandle(
            session
        );

        return false;
    }

    bool success = false;

    if (WinHttpSendRequest(
        request,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    ))
    {
        if (WinHttpReceiveResponse(
            request,
            nullptr
        ))
        {
            DWORD statusCode = 0;

            DWORD statusSize =
                sizeof(statusCode);

            if (WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_STATUS_CODE |
                WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &statusCode,
                &statusSize,
                WINHTTP_NO_HEADER_INDEX
            ))
            {
                if (statusCode >= 200 &&
                    statusCode < 300)
                {
                    success = true;

                    while (true)
                    {
                        DWORD available = 0;

                        if (!WinHttpQueryDataAvailable(
                            request,
                            &available
                        ))
                        {
                            success = false;
                            break;
                        }

                        if (available == 0)
                            break;

                        std::vector<char> buffer(
                            available
                        );

                        DWORD read = 0;

                        if (!WinHttpReadData(
                            request,
                            buffer.data(),
                            available,
                            &read
                        ))
                        {
                            success = false;
                            break;
                        }

                        if (read == 0)
                            break;

                        response.append(
                            buffer.data(),
                            read
                        );
                    }
                }
            }
        }
    }

    WinHttpCloseHandle(
        request
    );

    WinHttpCloseHandle(
        connection
    );

    WinHttpCloseHandle(
        session
    );

    return success;
}

bool Updater::check(
    const std::string& versionUrl
)
{
    std::wstring host;
    std::wstring path;

    INTERNET_PORT port = 0;
    bool secure = false;

    if (!parseURL(
        versionUrl,
        host,
        path,
        port,
        secure
    ))
    {
        return false;
    }

    std::string response;

    if (!httpGet(
        host,
        path,
        port,
        secure,
        response
    ))
    {
        return false;
    }

    return !response.empty();
}

bool Updater::download(
    const std::string& url,
    const std::string& destination
)
{
    std::wstring host;
    std::wstring path;

    INTERNET_PORT port = 0;
    bool secure = false;

    if (!parseURL(
        url,
        host,
        path,
        port,
        secure
    ))
    {
        return false;
    }

    std::string response;

    if (!httpGet(
        host,
        path,
        port,
        secure,
        response
    ))
    {
        return false;
    }

    if (response.empty())
        return false;

    std::string temporary =
        destination + ".new";

    {
        std::ofstream file(
            temporary,
            std::ios::binary
        );

        if (!file.is_open())
            return false;

        file.write(
            response.data(),
            static_cast<std::streamsize>(
                response.size()
                )
        );

        if (!file.good())
        {
            file.close();

            DeleteFileA(
                temporary.c_str()
            );

            return false;
        }
    }

    if (!MoveFileExA(
        temporary.c_str(),
        destination.c_str(),
        MOVEFILE_REPLACE_EXISTING |
        MOVEFILE_WRITE_THROUGH
    ))
    {
        DeleteFileA(
            temporary.c_str()
        );

        return false;
    }

    return true;
}

bool Updater::calculateSHA256(
    const std::string& filePath,
    std::string& hash
)
{
    hash.clear();

    std::ifstream file(
        filePath,
        std::ios::binary
    );

    if (!file.is_open())
        return false;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;

    PUCHAR hashObject = nullptr;
    PUCHAR hashBuffer = nullptr;

    DWORD objectSize = 0;
    DWORD hashSize = 0;
    DWORD bytesRead = 0;

    NTSTATUS result =
        BCryptOpenAlgorithmProvider(
            &algorithm,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            0
        );

    if (result < 0)
        return false;

    result =
        BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(
                &objectSize
                ),
            sizeof(objectSize),
            &bytesRead,
            0
        );

    if (result < 0)
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    result =
        BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(
                &hashSize
                ),
            sizeof(hashSize),
            &bytesRead,
            0
        );

    if (result < 0)
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    hashObject =
        new (std::nothrow) UCHAR[objectSize];

    hashBuffer =
        new (std::nothrow) UCHAR[hashSize];

    if (!hashObject ||
        !hashBuffer)
    {
        delete[] hashObject;
        delete[] hashBuffer;

        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    result =
        BCryptCreateHash(
            algorithm,
            &hashHandle,
            hashObject,
            objectSize,
            nullptr,
            0,
            0
        );

    if (result < 0)
    {
        delete[] hashObject;
        delete[] hashBuffer;

        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return false;
    }

    std::vector<char> buffer(
        1024 * 1024
    );

    bool success = true;

    while (file)
    {
        file.read(
            buffer.data(),
            static_cast<std::streamsize>(
                buffer.size()
                )
        );

        std::streamsize count =
            file.gcount();

        if (count > 0)
        {
            result =
                BCryptHashData(
                    hashHandle,
                    reinterpret_cast<PUCHAR>(
                        buffer.data()
                        ),
                    static_cast<ULONG>(
                        count
                        ),
                    0
                );

            if (result < 0)
            {
                success = false;
                break;
            }
        }
    }

    if (success)
    {
        result =
            BCryptFinishHash(
                hashHandle,
                hashBuffer,
                hashSize,
                0
            );

        if (result < 0)
        {
            success = false;
        }
    }

    if (success)
    {
        static constexpr char hex[] =
            "0123456789abcdef";

        hash.reserve(
            hashSize * 2
        );

        for (DWORD i = 0; i < hashSize; ++i)
        {
            hash.push_back(
                hex[
                    (hashBuffer[i] >> 4) &
                        0x0F
                ]
            );

            hash.push_back(
                hex[
                    hashBuffer[i] &
                        0x0F
                ]
            );
        }
    }

    BCryptDestroyHash(
        hashHandle
    );

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    delete[] hashObject;
    delete[] hashBuffer;

    return success;
}

bool Updater::loadLocalVersion(
    const std::string& path,
    int& version
)
{
    version = 0;

    std::ifstream file(
        path
    );

    if (!file.is_open())
        return false;

    std::string value;

    std::getline(
        file,
        value
    );

    value =
        Trim(value);

    if (value.empty())
        return false;

    try
    {
        version =
            std::stoi(value);
    }
    catch (...)
    {
        version = 0;
        return false;
    }

    return true;
}

bool Updater::saveLocalVersion(
    const std::string& path,
    int version
)
{
    std::ofstream file(
        path,
        std::ios::trunc
    );

    if (!file.is_open())
        return false;

    file << version;

    return file.good();
}

bool Updater::parseManifest(
    const std::string& manifest,
    UpdateInfo& info
)
{
    info = {};

    std::string version;
    std::string url;
    std::string sha256;
    std::string size;

    if (!ExtractManifestValue(
        manifest,
        "version",
        version
    ))
    {
        return false;
    }

    if (!ExtractManifestValue(
        manifest,
        "url",
        url
    ))
    {
        return false;
    }

    ExtractManifestValue(
        manifest,
        "sha256",
        sha256
    );

    ExtractManifestValue(
        manifest,
        "size",
        size
    );

    try
    {
        info.version =
            std::stoi(version);
    }
    catch (...)
    {
        return false;
    }

    info.url = url;
    info.sha256 = ToLower(
        Trim(sha256)
    );

    if (!size.empty())
    {
        try
        {
            info.size =
                std::stoull(size);
        }
        catch (...)
        {
            info.size = 0;
        }
    }

    return info.version >= 0 &&
        !info.url.empty();
}

bool Updater::verifyFile(
    const std::string& path,
    const UpdateInfo& info
)
{
    std::ifstream file(
        path,
        std::ios::binary |
        std::ios::ate
    );

    if (!file.is_open())
        return false;

    std::streampos fileSize =
        file.tellg();

    if (fileSize < 0)
        return false;

    if (info.size != 0 &&
        static_cast<unsigned long long>(
            fileSize
            ) != info.size)
    {
        return false;
    }

    if (!info.sha256.empty())
    {
        std::string actualHash;

        if (!calculateSHA256(
            path,
            actualHash
        ))
        {
            return false;
        }

        if (ToLower(actualHash) !=
            ToLower(info.sha256))
        {
            return false;
        }
    }

    return true;
}

bool Updater::updateDatabase(
    const std::string& manifestUrl,
    const std::string& localDatabase,
    const std::string& localVersionFile,
    std::string& status
)
{
    status.clear();

    std::wstring host;
    std::wstring path;

    INTERNET_PORT port = 0;
    bool secure = false;

    if (!parseURL(
        manifestUrl,
        host,
        path,
        port,
        secure
    ))
    {
        status =
            "Invalid manifest URL";

        return false;
    }

    std::string manifest;

    if (!httpGet(
        host,
        path,
        port,
        secure,
        manifest
    ))
    {
        status =
            "Failed to download manifest";

        return false;
    }

    if (manifest.empty())
    {
        status =
            "Manifest is empty";

        return false;
    }

    UpdateInfo info;

    if (!parseManifest(
        manifest,
        info
    ))
    {
        status =
            "Failed to parse manifest";

        return false;
    }

    int localVersion = 0;

    loadLocalVersion(
        localVersionFile,
        localVersion
    );

    if (info.version <= localVersion)
    {
        status =
            "Database is up to date";

        return true;
    }

    if (!download(
        info.url,
        localDatabase
    ))
    {
        status =
            "Failed to download database";

        return false;
    }

    if (!verifyFile(
        localDatabase,
        info
    ))
    {
        status =
            "Database verification failed";

        return false;
    }

    if (!saveLocalVersion(
        localVersionFile,
        info.version
    ))
    {
        status =
            "Failed to save database version";

        return false;
    }

    status =
        "Database updated successfully";

    return true;
}