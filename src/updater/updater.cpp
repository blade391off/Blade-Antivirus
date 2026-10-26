#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "updater.h"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <sstream>
#include <string_view>
#include <unordered_set>

#pragma comment(lib, "winhttp.lib")

namespace
{
    constexpr char DEFAULT_SOURCE[] =
        "https://raw.githubusercontent.com/romainmarcoux/malicious-hash/"
        "main/full-hash-sha256-{part}.txt";

    constexpr long long UPDATE_INTERVAL_SECONDS = 6 * 60 * 60;
    constexpr std::size_t MAX_RESPONSE_SIZE = 32u * 1024u * 1024u;
    constexpr std::size_t MAX_HASH_ENTRIES = 1000000; // ~32 MB in RAM
    constexpr int MAX_PARTS = 16;

    using Digest = std::array<std::uint8_t, 32>;

    struct DigestHash
    {
        std::size_t operator()(const Digest& d) const noexcept
        {
            std::size_t h = 0;
            std::memcpy(&h, d.data(), sizeof(h)); // SHA-256 output is uniform
            return h;
        }
    };

    std::string_view TrimView(std::string_view v)
    {
        const std::size_t first = v.find_first_not_of(" \t\r\n");

        if (first == std::string_view::npos)
            return {};

        const std::size_t last = v.find_last_not_of(" \t\r\n");
        return v.substr(first, last - first + 1);
    }

    int HexValue(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    bool ParseDigest(std::string_view hex, Digest& out)
    {
        if (hex.size() != 64)
            return false;

        for (std::size_t i = 0; i < 32; ++i)
        {
            const int hi = HexValue(hex[2 * i]);
            const int lo = HexValue(hex[2 * i + 1]);

            if (hi < 0 || lo < 0)
                return false;

            out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }

        return true;
    }

    void AppendDigest(std::string& out, const Digest& d)
    {
        static const char kDigits[] = "0123456789abcdef";

        for (std::uint8_t b : d)
        {
            out.push_back(kDigits[b >> 4]);
            out.push_back(kDigits[b & 0x0F]);
        }

        out.push_back('\n');
    }

    // Parses a downloaded list: one hash per line, '#' comments, BOM tolerated.
    void ParseHashes(std::string_view input, std::vector<Digest>& out)
    {
        if (input.size() >= 3
            && static_cast<unsigned char>(input[0]) == 0xEF
            && static_cast<unsigned char>(input[1]) == 0xBB
            && static_cast<unsigned char>(input[2]) == 0xBF)
        {
            input.remove_prefix(3);
        }

        while (!input.empty())
        {
            const std::size_t newline = input.find('\n');
            std::string_view line = TrimView(input.substr(0, newline));

            input = (newline == std::string_view::npos)
                ? std::string_view{}
                : input.substr(newline + 1);

            if (line.empty() || line[0] == '#')
                continue;

            const std::size_t ws = line.find_first_of(" \t,;");

            if (ws != std::string_view::npos)
                line = line.substr(0, ws);

            Digest d{};

            if (ParseDigest(line, d))
                out.push_back(d);
        }
    }

    std::string PartName(int index)
    {
        std::string name(2, 'a');
        name[0] = static_cast<char>('a' + index / 26);
        name[1] = static_cast<char>('a' + index % 26);
        return name;
    }

    // temp file -> flush to disk -> atomic replace
    bool AtomicWrite(
        const std::filesystem::path& destination,
        std::string_view content,
        std::string& error)
    {
        std::error_code ec;
        const std::filesystem::path parent = destination.parent_path();

        if (!parent.empty())
        {
            std::filesystem::create_directories(parent, ec);

            if (ec)
            {
                error = "Cannot create database directory: " + ec.message();
                return false;
            }
        }

        const std::wstring finalPath = destination.wstring();
        const std::wstring tempPath = finalPath + L".tmp";

        HANDLE file = CreateFileW(
            tempPath.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file == INVALID_HANDLE_VALUE)
        {
            error = "Cannot create temporary file. Windows error: "
                + std::to_string(GetLastError());
            return false;
        }

        bool ok = true;
        std::size_t offset = 0;

        while (offset < content.size())
        {
            const DWORD chunk = static_cast<DWORD>(
                std::min<std::size_t>(content.size() - offset, 1u << 20));
            DWORD written = 0;

            if (!WriteFile(file, content.data() + offset, chunk, &written, nullptr)
                || written == 0)
            {
                ok = false;
                break;
            }

            offset += written;
        }

        if (ok)
            ok = FlushFileBuffers(file) != 0;

        const DWORD writeError = ok ? 0 : GetLastError();
        CloseHandle(file);

        if (!ok)
        {
            DeleteFileW(tempPath.c_str());
            error = "Cannot write temporary file. Windows error: "
                + std::to_string(writeError);
            return false;
        }

        if (!MoveFileExW(
                tempPath.c_str(),
                finalPath.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            const DWORD code = GetLastError();
            DeleteFileW(tempPath.c_str());

            error = "Cannot replace database file. Windows error: "
                + std::to_string(code);
            return false;
        }

        return true;
    }

    // State file (tab separated):
    //   checked <TAB> <unix time of last successful check>
    //   etag    <TAB> <url> <TAB> <ETag from the last download>
    struct State
    {
        long long checked = 0;
        std::map<std::string, std::string> etags;
    };

    bool IsValidEtag(std::string_view etag)
    {
        if (etag.empty() || etag.size() > 256)
            return false;

        return std::all_of(etag.begin(), etag.end(), [](unsigned char c)
        {
            return c > 0x20 && c < 0x7F; // printable, no spaces/CR/LF
        });
    }

    State LoadState(const std::filesystem::path& statePath)
    {
        State state;
        std::ifstream file(statePath);
        std::string line;

        while (std::getline(file, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            const std::size_t t1 = line.find('\t');

            if (t1 == std::string::npos)
                continue;

            const std::string kind = line.substr(0, t1);

            if (kind == "checked")
            {
                state.checked = std::strtoll(line.c_str() + t1 + 1, nullptr, 10);
            }
            else if (kind == "etag")
            {
                const std::size_t t2 = line.find('\t', t1 + 1);

                if (t2 == std::string::npos)
                    continue;

                const std::string url = line.substr(t1 + 1, t2 - t1 - 1);
                const std::string etag = line.substr(t2 + 1);

                if (IsValidEtag(etag))
                    state.etags[url] = etag;
            }
        }

        return state;
    }

    bool SaveState(
        const std::filesystem::path& statePath,
        const State& state,
        std::string& error)
    {
        std::ostringstream content;
        content << "checked\t" << state.checked << '\n';

        for (const auto& entry : state.etags)
            content << "etag\t" << entry.first << '\t' << entry.second << '\n';

        return AtomicWrite(statePath, content.str(), error);
    }

    long long CurrentTimestamp()
    {
        return static_cast<long long>(std::time(nullptr));
    }

    struct WinHttpHandle
    {
        HINTERNET h = nullptr;
        ~WinHttpHandle() { if (h) WinHttpCloseHandle(h); }
    };

    // Reads one response header as printable ASCII; empty if absent.
    std::string QueryHeaderAscii(HINTERNET request, DWORD infoLevel)
    {
        DWORD size = 0;

        WinHttpQueryHeaders(
            request, infoLevel, WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER, &size, WINHTTP_NO_HEADER_INDEX);

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER
            || size < sizeof(wchar_t))
        {
            return {};
        }

        std::wstring buffer(size / sizeof(wchar_t), L'\0');

        if (!WinHttpQueryHeaders(
                request, infoLevel, WINHTTP_HEADER_NAME_BY_INDEX,
                &buffer[0], &size, WINHTTP_NO_HEADER_INDEX))
        {
            return {};
        }

        buffer.resize(size / sizeof(wchar_t));

        std::string out;

        for (wchar_t c : buffer)
        {
            if (c <= 0x20 || c >= 0x7F)
                return {};

            out.push_back(static_cast<char>(c));
        }

        return out;
    }
}

std::vector<std::string> Updater::defaultSources()
{
    return { DEFAULT_SOURCE };
}

std::vector<std::string> Updater::loadSources(
    const std::filesystem::path& configPath)
{
    std::vector<std::string> sources;
    std::ifstream file(configPath);
    std::string line;

    while (std::getline(file, line))
    {
        const std::string_view trimmed = TrimView(line);

        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        if (trimmed.rfind("https://", 0) == 0)
            sources.emplace_back(trimmed);
    }

    if (sources.empty())
        return defaultSources();

    return sources;
}

Updater::FetchStatus Updater::httpGet(
    const std::string& url,
    const std::string& etag,
    std::string& response,
    std::string& newEtag,
    std::string& error)
{
    response.clear();
    newEtag.clear();
    error.clear();

    if (url.rfind("https://", 0) != 0)
    {
        error = "HTTPS is required";
        return FetchStatus::Error;
    }

    const int required = MultiByteToWideChar(
        CP_UTF8, 0, url.c_str(), -1, nullptr, 0);

    if (required <= 1)
    {
        error = "Invalid URL";
        return FetchStatus::Error;
    }

    std::wstring wideUrl(static_cast<std::size_t>(required), L'\0');

    if (!MultiByteToWideChar(
            CP_UTF8, 0, url.c_str(), -1, &wideUrl[0], required))
    {
        error = "Cannot convert URL";
        return FetchStatus::Error;
    }

    wideUrl.resize(static_cast<std::size_t>(required - 1));

    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &components)
        || components.nScheme != INTERNET_SCHEME_HTTPS)
    {
        error = "Cannot parse URL (HTTPS required)";
        return FetchStatus::Error;
    }

    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);

    if (components.dwExtraInfoLength > 0)
        path.append(components.lpszExtraInfo, components.dwExtraInfoLength);

    if (path.empty())
        path = L"/";

    WinHttpHandle session;
    session.h = WinHttpOpen(
        L"BladeAntivirus/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!session.h)
    {
        error = "WinHttpOpen failed";
        return FetchStatus::Error;
    }

    WinHttpSetTimeouts(session.h, 10000, 10000, 15000, 20000);

    WinHttpHandle connection;
    connection.h = WinHttpConnect(session.h, host.c_str(), components.nPort, 0);

    if (!connection.h)
    {
        error = "WinHttpConnect failed";
        return FetchStatus::Error;
    }

    WinHttpHandle request;
    request.h = WinHttpOpenRequest(
        connection.h,
        L"GET",
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!request.h)
    {
        error = "WinHttpOpenRequest failed";
        return FetchStatus::Error;
    }

    // WinHTTP follows redirects itself (relative Location included);
    // https -> http downgrades are refused.
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(
        request.h, WINHTTP_OPTION_REDIRECT_POLICY,
        &redirectPolicy, sizeof(redirectPolicy));

#ifdef WINHTTP_OPTION_DECOMPRESSION
    DWORD decompression = WINHTTP_DECOMPRESSION_FLAG_ALL;
    WinHttpSetOption(
        request.h, WINHTTP_OPTION_DECOMPRESSION,
        &decompression, sizeof(decompression)); // less traffic; failure is harmless
#endif

    if (IsValidEtag(etag))
    {
        const std::wstring header =
            L"If-None-Match: " + std::wstring(etag.begin(), etag.end());

        WinHttpAddRequestHeaders(
            request.h,
            header.c_str(),
            static_cast<DWORD>(header.size()),
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    if (!WinHttpSendRequest(
            request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        || !WinHttpReceiveResponse(request.h, nullptr))
    {
        error = "HTTPS request failed. Windows error: "
            + std::to_string(GetLastError());
        return FetchStatus::Error;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);

    if (!WinHttpQueryHeaders(
            request.h,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusSize,
            WINHTTP_NO_HEADER_INDEX))
    {
        error = "Could not query HTTP status code";
        return FetchStatus::Error;
    }

    if (statusCode == 304)
        return FetchStatus::NotModified;

    if (statusCode == 404 || statusCode == 410)
        return FetchStatus::NotFound;

    if (statusCode < 200 || statusCode >= 300)
    {
        error = "HTTP " + std::to_string(statusCode);
        return FetchStatus::Error;
    }

    const std::string receivedEtag =
        QueryHeaderAscii(request.h, WINHTTP_QUERY_ETAG);

    if (IsValidEtag(receivedEtag))
        newEtag = receivedEtag;

    std::vector<char> buffer(64 * 1024);

    for (;;)
    {
        DWORD downloaded = 0;

        if (!WinHttpReadData(
                request.h,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &downloaded))
        {
            error = "Cannot read response";
            response.clear();
            return FetchStatus::Error;
        }

        if (downloaded == 0)
            break;

        if (response.size() + downloaded > MAX_RESPONSE_SIZE)
        {
            error = "File exceeds the 32 MB limit";
            response.clear();
            return FetchStatus::Error;
        }

        response.append(buffer.data(), downloaded);
    }

    if (response.empty())
    {
        error = "Empty response";
        return FetchStatus::Error;
    }

    return FetchStatus::Ok;
}

bool Updater::updateHashes(
    const std::filesystem::path& hashesPath,
    const std::filesystem::path& statePath,
    const std::vector<std::string>& sources,
    std::string& status,
    bool force,
    std::function<void(const std::string&)> progressCallback)
{
    State state = LoadState(statePath);
    const long long now = CurrentTimestamp();

    std::error_code ec;
    const bool databaseExists = std::filesystem::is_regular_file(hashesPath, ec);

    if (!force && databaseExists
        && state.checked > 0
        && now >= state.checked
        && now - state.checked < UPDATE_INTERVAL_SECONDS)
    {
        status = "[SKIP] Next check in less than 6 hours.\nHash database is up to date.";
        return true;
    }

    struct Part
    {
        std::string url;
        std::string etag;
        std::vector<Digest> digests;
        bool downloaded = false;
    };

    std::vector<Part> parts;
    std::string error;

    const auto fail = [&status](const std::string& message)
    {
        status = "[ERROR] " + message + "\nThe previous database was kept.";
        return false;
    };

    // Pass 1: conditional requests (If-None-Match) for every file.
    for (const std::string& source : sources)
    {
        const std::size_t marker = source.find("{part}");
        const bool split = marker != std::string::npos;

        for (int i = 0; i < (split ? MAX_PARTS : 1); ++i)
        {
            std::string url = source;

            if (split)
                url.replace(marker, 6, PartName(i));

            if (progressCallback)
            {
                progressCallback(
                    "Checking hash list " + std::to_string(parts.size() + 1) + "...");
            }

            const auto known = state.etags.find(url);
            const std::string etag =
                (!force && databaseExists && known != state.etags.end())
                ? known->second
                : std::string();

            std::string response;
            std::string newEtag;

            const FetchStatus result = httpGet(url, etag, response, newEtag, error);

            if (result == FetchStatus::NotFound)
            {
                if (i == 0)
                    return fail(url + ": HTTP 404");

                break; // end of a split list
            }

            if (result == FetchStatus::Error)
                return fail(url + ": " + error);

            Part part;
            part.url = url;

            if (result == FetchStatus::Ok)
            {
                ParseHashes(response, part.digests);

                if (part.digests.empty())
                    return fail(url + ": no valid SHA-256 hashes in the file");

                part.etag = newEtag;
                part.downloaded = true;
            }
            else
            {
                part.etag = etag; // 304: nothing changed
            }

            parts.push_back(std::move(part));
        }
    }

    if (parts.empty())
        return fail("No sources configured");

    const bool anyChanged = std::any_of(
        parts.begin(), parts.end(),
        [](const Part& p) { return p.downloaded; });

    if (!anyChanged && databaseExists)
    {
        state.checked = now;

        std::string stateError;
        SaveState(statePath, state, stateError);

        status = "[OK] Hash lists have not changed.\nHash database is up to date.";
        return true;
    }

    // Pass 2: the database is rebuilt from ALL files, so files that answered
    // 304 are downloaded again (unconditionally).
    for (Part& part : parts)
    {
        if (part.downloaded)
            continue;

        if (progressCallback)
            progressCallback("Downloading " + part.url);

        std::string response;
        std::string newEtag;

        if (httpGet(part.url, {}, response, newEtag, error) != FetchStatus::Ok)
            return fail(part.url + ": " + (error.empty() ? "download failed" : error));

        ParseHashes(response, part.digests);

        if (part.digests.empty())
            return fail(part.url + ": no valid SHA-256 hashes in the file");

        part.etag = newEtag;
        part.downloaded = true;
    }

    // Union of all files (order preserved, duplicates removed).
    std::vector<Digest> merged;
    std::unordered_set<Digest, DigestHash> seen;

    for (const Part& part : parts)
    {
        for (const Digest& d : part.digests)
        {
            if (merged.size() >= MAX_HASH_ENTRIES)
                break;

            if (seen.insert(d).second)
                merged.push_back(d);
        }
    }

    // Sanity check: a broken or emptied source must not wipe a good database.
    if (databaseExists)
    {
        const std::uintmax_t oldBytes = std::filesystem::file_size(hashesPath, ec);
        const std::size_t oldCount = ec ? 0 : static_cast<std::size_t>(oldBytes / 65);

        if (oldCount >= 1000 && merged.size() < oldCount / 2)
        {
            return fail(
                "New lists contain " + std::to_string(merged.size())
                + " hashes, less than half of the current "
                + std::to_string(oldCount));
        }
    }

    if (progressCallback)
        progressCallback("Writing database...");

    std::string output;
    output.reserve(merged.size() * 65);

    for (const Digest& d : merged)
        AppendDigest(output, d);

    if (!AtomicWrite(hashesPath, output, error))
        return fail(error);

    // Remember ETags only after the database was written successfully.
    state.checked = now;

    for (const Part& part : parts)
    {
        if (part.etag.empty())
            state.etags.erase(part.url);
        else
            state.etags[part.url] = part.etag;
    }

    std::string stateError;
    const bool stateSaved = SaveState(statePath, state, stateError);

    std::ostringstream report;
    report << "[OK] " << merged.size() << " hashes from "
           << parts.size() << " file(s).";

    if (!stateSaved)
        report << "\n[WARNING] Could not save update timer: " << stateError;

    status = report.str();
    return true;
}
