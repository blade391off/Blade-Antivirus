#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "updater.h"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <iomanip>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace
{
    constexpr char URLHAUS_URL[] =
        "https://urlhaus.abuse.ch/downloads/text/";

    constexpr char MALWAREBAZAAR_SHA256_URL[] =
        "https://bazaar.abuse.ch/export/txt/sha256/recent/";

    constexpr char THREATFOX_IP_PORT_URL[] =
        "https://threatfox.abuse.ch/export/cleantext/ip-port/";

    constexpr long long UPDATE_INTERVAL_SECONDS = 86100;

    enum FeedType
    {
        FeedSha256,
        FeedUrl,
        FeedIpPort
    };

    std::string Trim(const std::string& value)
    {
        const size_t first = value.find_first_not_of(" \t\r\n");

        if (first == std::string::npos)
            return {};

        const size_t last = value.find_last_not_of(" \t\r\n");

        return value.substr(first, last - first + 1);
    }

    std::string Lowercase(std::string value)
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char c)
            {
                return static_cast<char>(std::tolower(c));
            });

        return value;
    }

    bool IsSha256(const std::string& value)
    {
        if (value.size() != 64)
            return false;

        return std::all_of(
            value.begin(),
            value.end(),
            [](unsigned char c)
            {
                return std::isxdigit(c) != 0;
            });
    }

    bool IsUrl(const std::string& value)
    {
        return value.rfind("https://", 0) == 0 ||
            value.rfind("http://", 0) == 0;
    }

    bool IsIPv4Port(const std::string& value)
    {
        const size_t colon = value.find(':');

        if (colon == std::string::npos ||
            value.find(':', colon + 1) != std::string::npos)
        {
            return false;
        }

        const std::string ip = value.substr(0, colon);
        const std::string portText = value.substr(colon + 1);

        if (ip.empty() || portText.empty())
            return false;

        int octets = 0;
        size_t start = 0;

        while (start < ip.size())
        {
            const size_t dot = ip.find('.', start);
            const size_t end =
                dot == std::string::npos ? ip.size() : dot;

            const std::string part = ip.substr(start, end - start);

            if (part.empty() || part.size() > 3)
                return false;

            int number = 0;

            for (unsigned char c : part)
            {
                if (!std::isdigit(c))
                    return false;

                number = number * 10 + (c - '0');
            }

            if (number > 255)
                return false;

            ++octets;

            if (dot == std::string::npos)
                break;

            start = dot + 1;

            if (start >= ip.size())
                return false;
        }

        if (octets != 4)
            return false;

        int port = 0;

        for (unsigned char c : portText)
        {
            if (!std::isdigit(c))
                return false;

            port = port * 10 + (c - '0');

            if (port > 65535)
                return false;
        }

        return port >= 1 && port <= 65535;
    }

    std::string GetIP(const std::string& ipPort)
    {
        const size_t colon = ipPort.find(':');

        if (colon == std::string::npos)
            return {};

        return ipPort.substr(0, colon);
    }

    std::string Sha256String(const std::string& input)
    {
        BCRYPT_ALG_HANDLE algorithm = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objectSize = 0;
        DWORD hashSize = 0;
        DWORD resultSize = 0;

        if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            return {};

        if (BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&objectSize),
            sizeof(objectSize), &resultSize, 0) < 0 ||
            BCryptGetProperty(
            algorithm, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashSize),
            sizeof(hashSize), &resultSize, 0) < 0)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return {};
        }

        std::vector<UCHAR> object(objectSize);
        std::vector<UCHAR> digest(hashSize);

        NTSTATUS status = BCryptCreateHash(
            algorithm, &hash, object.data(), objectSize,
            nullptr, 0, 0);

    if (status >= 0 && !input.empty())
        status = BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(
                const_cast<char*>(input.data())),
            static_cast<ULONG>(input.size()), 0);

        if (status >= 0)
            status = BCryptFinishHash(
                hash, digest.data(), hashSize, 0);

        if (hash)
            BCryptDestroyHash(hash);

        BCryptCloseAlgorithmProvider(algorithm, 0);

        if (status < 0)
            return {};

        std::ostringstream output;
        output << std::hex << std::setfill('0');

        for (UCHAR byte : digest)
            output << std::setw(2) << static_cast<unsigned>(byte);

        return output.str();
    }

    bool NormalizeFeed(
        const std::string& input,
        FeedType type,
        std::string& output,
        size_t& count)
    {
        std::istringstream stream(input);
        std::string line;
        std::set<std::string> uniqueEntries;
        std::set<std::string> uniqueIPs;
        std::vector<std::string> entries;

        while (std::getline(stream, line))
        {
            line = Trim(line);

            if (line.empty() || line[0] == '#')
                continue;

            if (line.size() >= 3 &&
                static_cast<unsigned char>(line[0]) == 0xEF &&
                static_cast<unsigned char>(line[1]) == 0xBB &&
                static_cast<unsigned char>(line[2]) == 0xBF)
            {
                line.erase(0, 3);
                line = Trim(line);
            }

            if (line.empty() || line[0] == '#')
                continue;

            if (type == FeedSha256)
            {
                line = Lowercase(line);

                if (!IsSha256(line))
                    continue;

                if (uniqueEntries.insert(line).second)
                    entries.push_back(line);
            }
            else if (type == FeedUrl)
            {
                const size_t whitespace = line.find_first_of(" \t");

                if (whitespace != std::string::npos)
                    line = line.substr(0, whitespace);

                if (!IsUrl(line))
                    continue;

                const std::string hash = Sha256String(line);

                if (hash.empty())
                    continue;

                if (uniqueEntries.insert(hash).second)
                    entries.push_back(hash);
            }
            else if (type == FeedIpPort)
            {
                const size_t whitespace = line.find_first_of(" \t");

                if (whitespace != std::string::npos)
                    line = line.substr(0, whitespace);

                if (!IsIPv4Port(line))
                    continue;

                const std::string ip = GetIP(line);

                if (uniqueIPs.insert(ip).second)
                    entries.push_back(line);
            }
        }

        if (entries.empty())
            return false;

        output.clear();

        for (const std::string& entry : entries)
        {
            output += entry;
            output += "\r\n";
        }

        count = entries.size();
        return true;
    }

    bool AtomicWrite(
        const std::string& destination,
        const std::string& content,
        std::string& error)
    {
        const std::filesystem::path destinationPath(destination);
        const std::filesystem::path parent = destinationPath.parent_path();

        std::error_code ec;

        if (!parent.empty())
        {
            std::filesystem::create_directories(parent, ec);

            if (ec)
            {
                error = "Cannot create database directory: " +
                    ec.message();

                return false;
            }
        }

        const std::string temporary = destination + ".tmp";

        {
            std::ofstream file(
                temporary,
                std::ios::binary | std::ios::trunc);

            if (!file)
            {
                error = "Cannot create temporary file";
                return false;
            }

            file.write(
                content.data(),
                static_cast<std::streamsize>(content.size()));

            file.flush();

            if (!file)
            {
                file.close();
                DeleteFileA(temporary.c_str());

                error = "Cannot write temporary file";
                return false;
            }
        }

        if (!MoveFileExA(
            temporary.c_str(),
            destination.c_str(),
            MOVEFILE_REPLACE_EXISTING |
            MOVEFILE_WRITE_THROUGH))
        {
            const DWORD code = GetLastError();

            DeleteFileA(temporary.c_str());

            error = "Cannot replace database file. Windows error: " +
                std::to_string(code);

            return false;
        }

        return true;
    }

    std::map<std::string, long long> LoadState(
        const std::string& statePath)
    {
        std::map<std::string, long long> state;
        std::ifstream file(statePath);

        std::string key;
        long long timestamp = 0;

        while (file >> key >> timestamp)
            state[key] = timestamp;

        return state;
    }

    bool SaveState(
        const std::string& statePath,
        const std::map<std::string, long long>& state,
        std::string& error)
    {
        std::ostringstream content;

        for (const auto& entry : state)
            content << entry.first << ' ' << entry.second << "\n";

        return AtomicWrite(statePath, content.str(), error);
    }

    long long CurrentTimestamp()
    {
        return static_cast<long long>(std::time(nullptr));
    }
}

bool Updater::httpGet(
    const std::string& url,
    std::string& response,
    std::string& error)
{
    response.clear();
    error.clear();
    // Support a small number of redirects and provide a clearer error
    // message including the HTTP status code and reason.
    const int MAX_REDIRECTS = 5;
    std::string currentUrl = url;

    for (int redirect = 0; redirect <= MAX_REDIRECTS; ++redirect)
    {
        if (currentUrl.rfind("https://", 0) != 0)
        {
            error = "HTTPS is required";
            return false;
        }

        const int required = MultiByteToWideChar(
            CP_UTF8,
            0,
            currentUrl.c_str(),
            -1,
            nullptr,
            0);

        if (required <= 1)
        {
            error = "Invalid URL";
            return false;
        }

        std::wstring wideUrl(static_cast<size_t>(required), L'\0');

        if (!MultiByteToWideChar(
            CP_UTF8,
            0,
            currentUrl.c_str(),
            -1,
            &wideUrl[0],
            required))
        {
            error = "Cannot convert URL";
            return false;
        }

        wideUrl.resize(static_cast<size_t>(required - 1));

        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);
        components.dwSchemeLength = static_cast<DWORD>(-1);
        components.dwHostNameLength = static_cast<DWORD>(-1);
        components.dwUrlPathLength = static_cast<DWORD>(-1);
        components.dwExtraInfoLength = static_cast<DWORD>(-1);

        if (!WinHttpCrackUrl(
            wideUrl.c_str(),
            0,
            0,
            &components))
        {
            error = "Cannot parse URL";
            return false;
        }

        if (components.nScheme != INTERNET_SCHEME_HTTPS)
        {
            error = "HTTPS is required";
            return false;
        }

        const std::wstring host(
            components.lpszHostName,
            components.dwHostNameLength);

        std::wstring path(
            components.lpszUrlPath,
            components.dwUrlPathLength);

        if (components.dwExtraInfoLength > 0)
        {
            path.append(
                components.lpszExtraInfo,
                components.dwExtraInfoLength);
        }

        if (path.empty())
            path = L"/";

        HINTERNET session = WinHttpOpen(
            L"BladeAntivirus/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);

        if (!session)
        {
            error = "WinHttpOpen failed";
            return false;
        }

        WinHttpSetTimeouts(session, 10000, 10000, 15000, 20000);

        HINTERNET connection = WinHttpConnect(
            session,
            host.c_str(),
            components.nPort,
            0);

        if (!connection)
        {
            error = "WinHttpConnect failed";
            WinHttpCloseHandle(session);
            return false;
        }

        HINTERNET request = WinHttpOpenRequest(
            connection,
            L"GET",
            path.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (!request)
        {
            error = "WinHttpOpenRequest failed";
            WinHttpCloseHandle(connection);
            WinHttpCloseHandle(session);
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
            0) &&
            WinHttpReceiveResponse(request, nullptr))
        {
            DWORD statusCode = 0;
            DWORD statusSize = sizeof(statusCode);

            if (WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_STATUS_CODE |
                WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,
                &statusCode,
                &statusSize,
                WINHTTP_NO_HEADER_INDEX))
            {
                if (statusCode >= 200 && statusCode < 300)
                {
                    constexpr size_t MAX_RESPONSE_SIZE =
                        32 * 1024 * 1024;

                    success = true;

                    for (;;)
                    {
                        DWORD available = 0;

                        if (!WinHttpQueryDataAvailable(
                            request,
                            &available))
                        {
                            error = "Cannot read response size";
                            success = false;
                            break;
                        }

                        if (available == 0)
                            break;

                        if (response.size() + available >
                            MAX_RESPONSE_SIZE)
                        {
                            error = "Feed exceeds the 32 MB limit";
                            success = false;
                            break;
                        }

                        std::string buffer(available, '\0');
                        DWORD downloaded = 0;

                        if (!WinHttpReadData(
                            request,
                            &buffer[0],
                            available,
                            &downloaded))
                        {
                            error = "Cannot read response";
                            success = false;
                            break;
                        }

                        if (downloaded == 0)
                            break;

                        response.append(buffer.data(), downloaded);
                    }
                }
                else if (statusCode >= 300 && statusCode < 400 && redirect < MAX_REDIRECTS)
                {
                    // Follow redirect if Location header is provided.
                    DWORD bufSize = 0;

                    if (!WinHttpQueryHeaders(
                        request,
                        WINHTTP_QUERY_LOCATION,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        nullptr,
                        &bufSize,
                        WINHTTP_NO_HEADER_INDEX) &&
                        GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        std::vector<wchar_t> location(bufSize / sizeof(wchar_t));

                        if (WinHttpQueryHeaders(
                            request,
                            WINHTTP_QUERY_LOCATION,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &location[0],
                            &bufSize,
                            WINHTTP_NO_HEADER_INDEX))
                        {
                            // Convert wide location to UTF-8
                            const int needed = WideCharToMultiByte(
                                CP_UTF8,
                                0,
                                &location[0],
                                -1,
                                nullptr,
                                0,
                                nullptr,
                                nullptr);

                            if (needed > 1)
                            {
                                std::string newUrl(static_cast<size_t>(needed), '\0');

                                WideCharToMultiByte(
                                    CP_UTF8,
                                    0,
                                    &location[0],
                                    -1,
                                    &newUrl[0],
                                    needed,
                                    nullptr,
                                    nullptr);

                                newUrl.resize(static_cast<size_t>(needed - 1));
                                currentUrl = newUrl;
                                // Close handles and retry with new URL
                                WinHttpCloseHandle(request);
                                WinHttpCloseHandle(connection);
                                WinHttpCloseHandle(session);
                                continue;
                            }
                        }
                    }

                    error = "HTTP redirect without Location header";
                }
                else
                {
                    // Get status text if available
                    DWORD textSize = 0;

                    std::string statusText;

                    if (!WinHttpQueryHeaders(
                        request,
                        WINHTTP_QUERY_STATUS_TEXT,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        nullptr,
                        &textSize,
                        WINHTTP_NO_HEADER_INDEX) &&
                        GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                    {
                        std::vector<wchar_t> textBuf(textSize / sizeof(wchar_t));

                        if (WinHttpQueryHeaders(
                            request,
                            WINHTTP_QUERY_STATUS_TEXT,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &textBuf[0],
                            &textSize,
                            WINHTTP_NO_HEADER_INDEX))
                        {
                            const int needed = WideCharToMultiByte(
                                CP_UTF8,
                                0,
                                &textBuf[0],
                                -1,
                                nullptr,
                                0,
                                nullptr,
                                nullptr);

                            if (needed > 1)
                            {
                                statusText.assign(static_cast<size_t>(needed - 1), '\0');
                                WideCharToMultiByte(
                                    CP_UTF8,
                                    0,
                                    &textBuf[0],
                                    -1,
                                    &statusText[0],
                                    needed,
                                    nullptr,
                                    nullptr);
                            }
                        }
                    }

                    error = "HTTP response status is not successful";

                    if (!statusText.empty())
                    {
                        error += ": ";
                        error += statusText;
                    }

                    error += " (" + std::to_string(statusCode) + ")";
                }
            }
            else
            {
                error = "Could not query HTTP status code";
            }
        }
        else
        {
            error = "HTTPS request failed";
        }

        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);

        if (success && !response.empty())
            return true;

        // If we followed a redirect, the loop will continue; otherwise
        // break and return failure.
        break;
    }

    // Clear response on failure
    response.clear();
    return false;
}

bool Updater::updateFeed(
    const std::string& url,
    const std::string& destination,
    int type,
    size_t& count,
    std::string& error)
{
    count = 0;

    std::string response;

    if (!httpGet(url, response, error))
        return false;

    std::string normalized;

    if (!NormalizeFeed(
        response,
        static_cast<FeedType>(type),
        normalized,
        count))
    {
        error = "Feed contains no valid entries";
        return false;
    }

    if (!AtomicWrite(destination, normalized, error))
        return false;

    return true;
}

bool Updater::updateFeeds(
    const std::string& sha256Path,
    const std::string& urlPath,
    const std::string& ipPath,
    const std::string& statePath,
    std::string& status,
    bool force)
{
    std::ostringstream report;
    std::map<std::string, long long> state = LoadState(statePath);

    const long long now = CurrentTimestamp();
    int updated = 0;
    int skipped = 0;
    bool stateChanged = false;

    struct Feed
    {
        const char* key;
        const char* name;
        const char* url;
        const std::string* path;
        FeedType type;
    };

    const Feed feeds[] =
    {
        {
            "sha256",
            "MalwareBazaar SHA-256",
            MALWAREBAZAAR_SHA256_URL,
            &sha256Path,
            FeedSha256
        },
        {
            "urlhaus",
            "URLhaus",
            URLHAUS_URL,
            &urlPath,
            FeedUrl
        },
        {
            "threatfox",
            "ThreatFox IP:PORT",
            THREATFOX_IP_PORT_URL,
            &ipPath,
            FeedIpPort
        }
    };

    for (const Feed& feed : feeds)
    {
        const auto found = state.find(feed.key);

        if (!force &&
            found != state.end() &&
            now >= found->second &&
            now - found->second < UPDATE_INTERVAL_SECONDS)
        {
            report << "[SKIP] " << feed.name
                << ": next check in less than 23h 55m\n";

            ++skipped;
            continue;
        }

        size_t count = 0;
        std::string error;

        if (updateFeed(
            feed.url,
            *feed.path,
            feed.type,
            count,
            error))
        {
            state[feed.key] = CurrentTimestamp();
            stateChanged = true;
            ++updated;

            report << "[OK] " << feed.name
                << ": " << count << " entries\n";

            std::string stateError;

            if (!SaveState(statePath, state, stateError))
            {
                report << "[WARNING] Could not save update timer: "
                    << stateError << "\n";
            }
        }
        else
        {
            report << "[ERROR] " << feed.name
                << ": " << error << "\n";
        }
    }

    if (updated == 0 && skipped == 3)
    {
        report << "\nAll feeds are up to date.";
    }
    else
    {
        report << "\nUpdated: " << updated
            << "/3, skipped: " << skipped << "/3.";
    }

    status = report.str();

    return updated > 0 || skipped == 3;
}
