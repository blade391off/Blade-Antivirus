
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <filesystem>

#include "scanner.h"
#include "hash_detector.h"
#include "scanner/pe_analyzer.h"
#include "scanner/scan_cache.h"

#include <yara.h>

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cwctype>
#include <fstream>
#include <iterator>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <system_error>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef FILE_ATTRIBUTE_RECALL_ON_OPEN
#define FILE_ATTRIBUTE_RECALL_ON_OPEN 0x00040000
#endif

#ifndef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000
#endif

namespace
{
    // YARA rules live next to the executable in a release build, in the
    // source tree during development. BLADE_YARA_DIR overrides both.
    std::filesystem::path YaraRulesDirectory()
    {
        std::vector<std::filesystem::path> candidates;

        wchar_t fromEnvironment[32768]{};

        const DWORD environmentLength = GetEnvironmentVariableW(
            L"BLADE_YARA_DIR",
            fromEnvironment,
            static_cast<DWORD>(std::size(fromEnvironment)));

        if (environmentLength > 0
            && environmentLength < std::size(fromEnvironment))
        {
            candidates.emplace_back(fromEnvironment);
        }

        wchar_t modulePath[MAX_PATH]{};

        const DWORD moduleLength =
            GetModuleFileNameW(nullptr, modulePath, MAX_PATH);

        if (moduleLength > 0 && moduleLength < MAX_PATH)
        {
            candidates.push_back(
                std::filesystem::path(modulePath).parent_path() / L"yara");
        }

#ifdef BLADE_SOURCE_DIR
        candidates.push_back(
            std::filesystem::path(std::u8string(
                reinterpret_cast<const char8_t*>(BLADE_SOURCE_DIR)))
            / L"yara");
#endif

        std::error_code error;

        for (const auto& candidate : candidates)
        {
            if (std::filesystem::is_directory(candidate, error))
                return candidate;

            error.clear();
        }

        return {};
    }
}

#ifndef YARA_RULES_DIR
#define YARA_RULES_DIR "D:/BladeAntivirus/yara"
#endif

namespace
{
    constexpr DWORD kReadBufferSize = 256 * 1024;

    constexpr DWORD kCloudMask =
        FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    constexpr char kEmptySha256[] =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    std::once_flag gYaraInitFlag;
    int gYaraInitResult = ERROR_INTERNAL_ERROR;

    struct FileHandle
    {
        HANDLE h = INVALID_HANDLE_VALUE;

        ~FileHandle()
        {
            if (h != INVALID_HANDLE_VALUE)
                CloseHandle(h);
        }
    };

    struct HashHandle
    {
        BCRYPT_HASH_HANDLE h = nullptr;

        ~HashHandle()
        {
            if (h)
                BCryptDestroyHash(h);
        }
    };

    struct YaraCompilerHandle
    {
        YR_COMPILER* h = nullptr;

        ~YaraCompilerHandle()
        {
            if (h)
                yr_compiler_destroy(h);
        }
    };

    std::wstring ToWin32Path(
        const std::filesystem::path& input)
    {
        std::filesystem::path p = input;
        std::wstring s = p.make_preferred().wstring();

        if (s.size() < 240 || s.rfind(L"\\\\?\\", 0) == 0)
            return s;

        if (s.rfind(L"\\\\", 0) == 0)
            return L"\\\\?\\UNC\\" + s.substr(2);

        if (s.size() >= 2 && s[1] == L':')
            return L"\\\\?\\" + s;

        return s;
    }

    std::string WideToUtf8(const std::wstring& input)
    {
        if (input.empty())
            return {};

        const int required = WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            input.data(),
            static_cast<int>(input.size()),
            nullptr,
            0,
            nullptr,
            nullptr);

        if (required <= 0)
            return {};

        std::string output(
            static_cast<std::size_t>(required),
            '\0');

        if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            input.data(),
            static_cast<int>(input.size()),
            output.data(),
            required,
            nullptr,
            nullptr) <= 0)
        {
            return {};
        }

        return output;
    }

    enum class PeProbe
    {
        No,
        Yes,
        Far
    };

    PeProbe ProbePE(
        const UCHAR* data,
        std::size_t size,
        std::uint64_t& farOffset)
    {
        if (size < sizeof(IMAGE_DOS_HEADER))
            return PeProbe::No;

        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos, data, sizeof(dos));

        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
            return PeProbe::No;

        const std::size_t offset =
            static_cast<std::size_t>(dos.e_lfanew);

        if (offset > size || size - offset < sizeof(DWORD))
        {
            farOffset = static_cast<std::uint64_t>(dos.e_lfanew);
            return PeProbe::Far;
        }

        DWORD signature = 0;
        std::memcpy(&signature, data + offset, sizeof(signature));

        return signature == IMAGE_NT_SIGNATURE
            ? PeProbe::Yes
            : PeProbe::No;
    }

    bool ReadPeSignatureAt(
        HANDLE file,
        std::uint64_t offset)
    {
        LARGE_INTEGER position{};
        position.QuadPart = static_cast<LONGLONG>(offset);

        if (!SetFilePointerEx(
            file,
            position,
            nullptr,
            FILE_BEGIN))
        {
            return false;
        }

        DWORD signature = 0;
        DWORD bytesRead = 0;

        return ReadFile(
            file,
            &signature,
            sizeof(signature),
            &bytesRead,
            nullptr)
            && bytesRead == sizeof(signature)
            && signature == IMAGE_NT_SIGNATURE;
    }

    std::string ToHex(
        const std::array<UCHAR, 32>& digest)
    {
        static const char kDigits[] =
            "0123456789abcdef";

        std::string output(64, '0');

        for (std::size_t i = 0; i < digest.size(); ++i)
        {
            output[2 * i] =
                kDigits[digest[i] >> 4];

            output[2 * i + 1] =
                kDigits[digest[i] & 0x0F];
        }

        return output;
    }

    ScanResult Error(
        ScanResult result,
        DWORD code)
    {
        result.verdict = "ERROR";
        result.winError = code;
        return result;
    }

    ScanResult Skipped(ScanResult result)
    {
        result.verdict = "SKIPPED";
        return result;
    }

    bool RunWinVerifyTrust(WINTRUST_DATA& data)
    {
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        const HWND noUi =
            reinterpret_cast<HWND>(INVALID_HANDLE_VALUE);

        data.cbStruct = sizeof(data);
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwProvFlags =
            WTD_CACHE_ONLY_URL_RETRIEVAL
            | WTD_REVOCATION_CHECK_NONE;

        data.dwStateAction = WTD_STATEACTION_VERIFY;

        const LONG status =
            WinVerifyTrust(noUi, &action, &data);

        data.dwStateAction = WTD_STATEACTION_CLOSE;

        WinVerifyTrust(noUi, &action, &data);

        return status == ERROR_SUCCESS;
    }

    bool VerifyEmbeddedSignature(
        const std::wstring& path)
    {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = path.c_str();

        WINTRUST_DATA data{};
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.pFile = &fileInfo;

        return RunWinVerifyTrust(data);
    }

    bool VerifyCatalogSignature(
        const std::wstring& path)
    {
        FileHandle file;

        file.h = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ
            | FILE_SHARE_WRITE
            | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (file.h == INVALID_HANDLE_VALUE)
            return false;

        HCATADMIN admin = nullptr;

        if (!CryptCATAdminAcquireContext(
            &admin,
            nullptr,
            0))
        {
            return false;
        }

        bool trusted = false;
        DWORD hashSize = 0;

        CryptCATAdminCalcHashFromFileHandle(
            file.h,
            &hashSize,
            nullptr,
            0);

        if (hashSize > 0 && hashSize <= 64)
        {
            std::vector<BYTE> hash(hashSize);

            if (CryptCATAdminCalcHashFromFileHandle(
                file.h,
                &hashSize,
                hash.data(),
                0))
            {
                HCATINFO catalog =
                    CryptCATAdminEnumCatalogFromHash(
                        admin,
                        hash.data(),
                        hashSize,
                        0,
                        nullptr);

                if (catalog)
                {
                    CATALOG_INFO info{};
                    info.cbStruct = sizeof(info);

                    if (CryptCATCatalogInfoFromContext(
                        catalog,
                        &info,
                        0))
                    {
                        static const wchar_t kHex[] =
                            L"0123456789ABCDEF";

                        std::wstring tag;

                        for (DWORD i = 0; i < hashSize; ++i)
                        {
                            tag.push_back(
                                kHex[hash[i] >> 4]);

                            tag.push_back(
                                kHex[hash[i] & 0x0F]);
                        }

                        WINTRUST_CATALOG_INFO catalogInfo{};
                        catalogInfo.cbStruct =
                            sizeof(catalogInfo);

                        catalogInfo.pcwszCatalogFilePath =
                            info.wszCatalogFile;

                        catalogInfo.pcwszMemberTag =
                            tag.c_str();

                        catalogInfo.pcwszMemberFilePath =
                            path.c_str();

                        catalogInfo.hMemberFile = file.h;
                        catalogInfo.pbCalculatedFileHash =
                            hash.data();

                        catalogInfo.cbCalculatedFileHash =
                            hashSize;

                        catalogInfo.hCatAdmin = admin;

                        WINTRUST_DATA data{};
                        data.dwUnionChoice =
                            WTD_CHOICE_CATALOG;

                        data.pCatalog = &catalogInfo;

                        trusted = RunWinVerifyTrust(data);
                    }

                    CryptCATAdminReleaseCatalogContext(
                        admin,
                        catalog,
                        0);
                }
            }
        }

        CryptCATAdminReleaseContext(admin, 0);

        return trusted;
    }

    bool IsTrustedSigned(
        const std::filesystem::path& filePath)
    {
        std::filesystem::path p = filePath;

        const std::wstring path =
            p.make_preferred().wstring();

        return VerifyEmbeddedSignature(path)
            || VerifyCatalogSignature(path);
    }

    std::string YaraDetails(const ScanResult& result)
    {
        std::string details = "YARA rule match";

        if (!result.yaraMatches.empty())
        {
            details += ": ";

            for (std::size_t i = 0; i < result.yaraMatches.size(); ++i)
            {
                if (i != 0)
                    details += ", ";

                details += result.yaraMatches[i];
            }
        }

        return details;
    }

    // A generic YARA rule can match vendor strings that legitimate signed
    // software contains too (an OR-ed "RDP", "+h", "interface"...). A valid
    // Authenticode signature from a trusted root is far stronger evidence, so
    // a YARA-only hit on a signed file is reported as suspicious instead of
    // malicious. A hash-database hit stays malicious regardless.
    void ApplyYaraVerdict(
        const std::filesystem::path& filePath,
        ScanResult& result)
    {
        if (!result.yaraMatch)
            return;

        result.details = YaraDetails(result);

        if (result.hashMatch)
            return;

        if (IsTrustedSigned(filePath))
        {
            result.verdict = "SUSPICIOUS";
            result.details +=
                " (digitally signed file, possible false positive)";
        }
    }

    std::uint64_t FileTimeToU64(
        const FILETIME& ft)
    {
        return
            (static_cast<std::uint64_t>(
                ft.dwHighDateTime) << 32)
            | ft.dwLowDateTime;
    }

    int YaraCallback(
        YR_SCAN_CONTEXT*,
        int message,
        void* messageData,
        void* userData)
    {
        if (message != CALLBACK_MSG_RULE_MATCHING)
            return CALLBACK_CONTINUE;

        if (!messageData || !userData)
            return CALLBACK_CONTINUE;

        auto* rule =
            static_cast<YR_RULE*>(messageData);

        auto* result =
            static_cast<ScanResult*>(userData);

        if (!rule->identifier)
            return CALLBACK_CONTINUE;

        const std::string name = rule->identifier;

        if (std::find(
            result->yaraMatches.begin(),
            result->yaraMatches.end(),
            name) == result->yaraMatches.end())
        {
            result->yaraMatches.push_back(name);
        }

        result->yaraMatch = true;

        return CALLBACK_CONTINUE;
    }

    std::vector<std::filesystem::path> FindYaraRules(
        const std::filesystem::path& directory)
    {
        std::vector<std::filesystem::path> rules;

        std::error_code error;

        if (!std::filesystem::exists(directory, error)
            || !std::filesystem::is_directory(directory, error))
        {
            return rules;
        }

        std::filesystem::recursive_directory_iterator iterator(
            directory,
            std::filesystem::directory_options::skip_permission_denied,
            error);

        const std::filesystem::recursive_directory_iterator end;

        while (iterator != end)
        {
            if (error)
            {
                error.clear();
                iterator.increment(error);
                continue;
            }

            const auto& entry = *iterator;

            std::error_code entryError;

            if (entry.is_regular_file(entryError)
                && !entryError)
            {
                const auto extension = entry.path().extension();

                if (extension == ".yar" || extension == ".yara")
                    rules.push_back(entry.path());
            }

            iterator.increment(error);
        }

        std::sort(
            rules.begin(),
            rules.end());

        return rules;
    }

    bool InitializeYara()
    {
        std::call_once(
            gYaraInitFlag,
            []()
            {
                gYaraInitResult = yr_initialize();
            });

        return gYaraInitResult == ERROR_SUCCESS;
    }

    struct YaraCompileState
    {
        // Directory that owns the ruleset; used as a fallback when a rule file
        // includes another one by a path relative to the ruleset root.
        std::filesystem::path root;

        // Files whose contents were already compiled. YARA does not dedupe
        // includes, so pulling the same file in twice produces "duplicate
        // rule identifier" errors; such repeats are fed as empty includes.
        std::unordered_set<std::wstring> provided;

        // Include spellings seen so far, mapped to the file they resolved to.
        // Needed because YARA reports nested includes by their spelled name,
        // not by an absolute path.
        std::unordered_map<std::wstring, std::filesystem::path> names;

        // Rule files that must not be compiled again (they failed once).
        std::unordered_set<std::wstring> blocked;

        // File reported by the last error, resolved to an absolute path.
        std::filesystem::path failedFile;

        int errors = 0;
        int warnings = 0;
    };

    std::wstring NormalizeKey(const std::filesystem::path& path)
    {
        std::wstring key = path.lexically_normal().wstring();

        for (wchar_t& ch : key)
            ch = static_cast<wchar_t>(std::towlower(ch));

        return key;
    }

    std::filesystem::path FromUtf8(const char* text)
    {
        if (!text)
            return {};

        return std::filesystem::path(std::u8string(
            reinterpret_cast<const char8_t*>(text)));
    }

    bool IsRegularFile(const std::filesystem::path& path)
    {
        std::error_code error;

        return !path.empty()
            && std::filesystem::is_regular_file(path, error);
    }

    // Resolves an `include "..."` argument to a real file.
    //
    // Rulesets are not consistent: some include paths are relative to the
    // including file, others to the ruleset root. Both are tried before
    // falling back to the process working directory.
    std::filesystem::path ResolveIncludePath(
        const YaraCompileState& state,
        const std::string& includeName,
        const char* callingRuleFileName)
    {
        const std::filesystem::path target = FromUtf8(includeName.c_str());

        if (target.empty())
            return {};

        if (target.is_absolute())
            return IsRegularFile(target) ? target : std::filesystem::path{};

        if (callingRuleFileName && *callingRuleFileName)
        {
            std::filesystem::path base;

            const auto known =
                state.names.find(NormalizeKey(
                    std::filesystem::path(FromUtf8(callingRuleFileName))));

            if (known != state.names.end())
            {
                base = known->second.parent_path();
            }
            else
            {
                const std::filesystem::path callingPath =
                    FromUtf8(callingRuleFileName);

                if (callingPath.is_absolute())
                    base = callingPath.parent_path();
            }

            if (!base.empty())
            {
                const std::filesystem::path candidate = base / target;

                if (IsRegularFile(candidate))
                    return candidate;
            }
        }

        const std::filesystem::path fromRoot = state.root / target;

        if (IsRegularFile(fromRoot))
            return fromRoot;

        if (IsRegularFile(target))
            return target;

        return {};
    }

    // An empty include keeps YARA happy while contributing no rules.
    const char* EmptyInclude()
    {
        auto* buffer = static_cast<char*>(std::malloc(2));

        if (!buffer)
            return nullptr;

        buffer[0] = '\n';
        buffer[1] = '\0';

        return buffer;
    }

    // YARA resolves `include "..."` against the process working directory by
    // default. Rulesets use paths like "./CVE/foo.yar" relative to their own
    // folder, so resolve them against the including file instead.
    const char* YaraIncludeCallback(
        const char* includeName,
        const char* callingRuleFileName,
        const char*,
        void* userData)
    {
        auto* state = static_cast<YaraCompileState*>(userData);

        if (!includeName || !*includeName || !state)
            return nullptr;

        const std::filesystem::path target =
            ResolveIncludePath(*state, includeName, callingRuleFileName);

        if (target.empty())
        {
            OutputDebugStringA(
                (std::string("[BladeAntivirus] YARA include not found: ")
                 + includeName + "\n").c_str());

            return nullptr;
        }

        const std::wstring key = NormalizeKey(target);

        // Broken file, or already compiled through another include.
        if (state->blocked.count(key) != 0
            || state->provided.count(key) != 0)
        {
            return EmptyInclude();
        }

        std::error_code error;
        const std::uintmax_t size =
            std::filesystem::file_size(target, error);

        if (error || size == 0 || size > (8ull << 20))
            return nullptr;

        std::ifstream file(target, std::ios::binary);

        if (!file)
            return nullptr;

        auto* buffer = static_cast<char*>(
            std::malloc(static_cast<std::size_t>(size) + 1));

        if (!buffer)
            return nullptr;

        file.read(buffer, static_cast<std::streamsize>(size));

        buffer[static_cast<std::size_t>(file.gcount())] = '\0';

        if (!file && !file.eof())
        {
            std::free(buffer);
            return nullptr;
        }

        state->provided.insert(key);
        state->names[NormalizeKey(
            std::filesystem::path(includeName))] = target;

        return buffer;
    }

    void YaraIncludeFree(const char* pointer, void*)
    {
        if (pointer)
            std::free(const_cast<char*>(pointer));
    }

    // Maps the file name reported by YARA back to a real file. Nested includes
    // are reported by the name they were spelled with.
    std::filesystem::path ResolveReportedFile(
        const YaraCompileState& state,
        const char* fileName)
    {
        if (!fileName || !*fileName)
            return {};

        const std::filesystem::path reported = FromUtf8(fileName);
        const std::wstring key = NormalizeKey(reported);

        const auto known = state.names.find(key);

        if (known != state.names.end())
            return known->second;

        if (reported.is_absolute())
            return reported;

        const std::filesystem::path fromRoot = state.root / reported;

        if (IsRegularFile(fromRoot))
            return fromRoot;

        return reported;
    }

    void YaraCompileCallback(
        int errorLevel,
        const char* fileName,
        int lineNumber,
        const YR_RULE*,
        const char* message,
        void* userData)
    {
        auto* state = static_cast<YaraCompileState*>(userData);

        const bool isError =
            errorLevel == YARA_ERROR_LEVEL_ERROR;

        if (state)
        {
            if (isError)
            {
                ++state->errors;

                const std::filesystem::path failed =
                    ResolveReportedFile(*state, fileName);

                if (!failed.empty())
                    state->failedFile = failed;
            }
            else
            {
                ++state->warnings;
            }
        }

        const char* kind = isError ? "error" : "warning";

        const std::string text =
            std::string("[BladeAntivirus] YARA ") + kind + ": "
            + (fileName ? fileName : "?") + ":"
            + std::to_string(lineNumber) + " "
            + (message ? message : "") + "\n";

        OutputDebugStringA(text.c_str());

        // Also visible when the engine runs without a debugger attached.
        std::fputs(text.c_str(), stderr);
    }


    bool IsAggregatorRule(const std::filesystem::path& path)
    {
        std::wstring name = path.filename().wstring();

        for (wchar_t& ch : name)
            ch = static_cast<wchar_t>(std::towlower(ch));

        return name == L"index.yar" || name == L"index.yara";
    }

    // Compiles all YARA rule files under `directory`.
    //
    // `index.yar` runs first because it pulls the whole set in through
    // `include`; anything it already loaded is skipped.
    //
    // A ruleset can contain a file that this libyara build cannot handle (for
    // example `import "macho"` when the module is not compiled in). YARA
    // refuses to accept further files after an error, so the compiler is
    // rebuilt from scratch with the offending file blocked, and the include
    // callback feeds an empty include for it. That keeps the rest usable.
    bool CompileYaraRules(
        const std::filesystem::path& directory,
        YR_RULES** output)
    {
        if (!output)
            return false;

        *output = nullptr;

        auto ruleFiles = FindYaraRules(directory);

        if (ruleFiles.empty())
        {
            OutputDebugStringW(
                L"[BladeAntivirus] No YARA rules found.\n");

            return true;
        }

        // Aggregator first, then everything else.
        std::stable_partition(
            ruleFiles.begin(),
            ruleFiles.end(),
            IsAggregatorRule);

        YaraCompileState state;
        state.root = directory;

        const std::size_t maxAttempts = ruleFiles.size() + 8;

        for (std::size_t attempt = 0; attempt < maxAttempts; ++attempt)
        {
            // Every attempt starts from a clean compiler: a compiler that saw
            // an error may not be reused.
            state.provided.clear();
            state.names.clear();
            state.failedFile.clear();
            state.errors = 0;
            state.warnings = 0;

            YaraCompilerHandle compiler;

            if (yr_compiler_create(&compiler.h) != ERROR_SUCCESS)
            {
                OutputDebugStringW(
                    L"[BladeAntivirus] Cannot create YARA compiler.\n");

                return false;
            }

            yr_compiler_set_callback(
                compiler.h,
                YaraCompileCallback,
                &state);

            yr_compiler_set_include_callback(
                compiler.h,
                YaraIncludeCallback,
                YaraIncludeFree,
                &state);

            bool compiled = true;
            std::filesystem::path failed;

            for (const auto& rulePath : ruleFiles)
            {
                const std::wstring key = NormalizeKey(rulePath);

                // Blocked by an earlier attempt, or already compiled as part
                // of another file through `include`.
                if (state.blocked.count(key) != 0
                    || state.provided.count(key) != 0)
                {
                    continue;
                }

                const std::wstring widePath = rulePath.wstring();

                FILE* file = _wfopen(widePath.c_str(), L"rb");

                if (!file)
                {
                    failed = rulePath;
                    compiled = false;
                    break;
                }

                const std::string fileName =
                    WideToUtf8(widePath);

                state.failedFile.clear();

                const int errors = yr_compiler_add_file(
                    compiler.h,
                    file,
                    nullptr,
                    fileName.c_str());

                fclose(file);

                if (errors != 0)
                {
                    const std::string text =
                        "[BladeAntivirus] YARA compilation failed: "
                        + WideToUtf8(widePath) + " | Errors: "
                        + std::to_string(errors) + "\n";

                    OutputDebugStringA(text.c_str());
                    std::fputs(text.c_str(), stderr);

                    failed = state.failedFile.empty()
                        ? rulePath
                        : state.failedFile;

                    compiled = false;
                    break;
                }

                // Mark as done so that a later `include` does not add it a
                // second time ("duplicate rule identifier").
                state.provided.insert(key);
            }

            if (compiled)
            {
                const int status =
                    yr_compiler_get_rules(
                        compiler.h,
                        output);

                if (status != ERROR_SUCCESS || !*output)
                {
                    *output = nullptr;

                    OutputDebugStringW(
                        L"[BladeAntivirus] Failed to obtain compiled YARA rules.\n");

                    return false;
                }

                OutputDebugStringW(
                    L"[BladeAntivirus] YARA rules compiled successfully.\n");

                return true;
            }

            // Block the file that could not be compiled and try again.
            if (!state.blocked.insert(NormalizeKey(failed)).second)
            {
                OutputDebugStringW(
                    L"[BladeAntivirus] YARA compiler makes no progress.\n");

                return false;
            }

            const std::string text =
                "[BladeAntivirus] YARA rule skipped: "
                + WideToUtf8(failed.wstring()) + "\n";

            OutputDebugStringA(text.c_str());
            std::fputs(text.c_str(), stderr);
        }

        OutputDebugStringW(
            L"[BladeAntivirus] YARA compilation gave up after repeated errors.\n");

        return false;
    }

    void ScanWithYara(
        YR_RULES* rules,
        const std::filesystem::path& filePath,
        ScanResult& result,
        int timeoutSeconds)
    {
        if (!rules)
            return;

        const std::string utf8Path =
            WideToUtf8(filePath.wstring());

        if (utf8Path.empty())
            return;

        const int status = yr_rules_scan_file(
            rules,
            utf8Path.c_str(),
            0,
            YaraCallback,
            &result,
            timeoutSeconds);

        if (status != ERROR_SUCCESS
            && status != ERROR_SCAN_TIMEOUT)
        {
            OutputDebugStringA(
                "[BladeAntivirus] YARA scan failed.\n");
        }
    }
}

struct Scanner::Impl
{
    BCRYPT_ALG_HANDLE alg = nullptr;

    DWORD objectSize = 0;

    std::vector<UCHAR> object;
    std::vector<UCHAR> buffer;
    std::vector<UCHAR> image;

    YR_RULES* yaraRules = nullptr;

    blade::ScanCache cache;

    std::filesystem::path cachePath;
    std::filesystem::path yaraRulesPath;

    ~Impl()
    {
        if (yaraRules)
            yr_rules_destroy(yaraRules);

        if (alg)
            BCryptCloseAlgorithmProvider(alg, 0);
    }
};

Scanner::Scanner() = default;

Scanner::~Scanner() = default;

bool Scanner::initialize(
    const std::filesystem::path& databasePath,
    const std::filesystem::path& cachePath)
{
    m_lastError.clear();

    auto impl = std::make_unique<Impl>();

    DWORD resultSize = 0;

    if (BCryptOpenAlgorithmProvider(
        &impl->alg,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0) < 0)
    {
        impl->alg = nullptr;
        m_lastError = "Cannot open the SHA-256 provider";
        return false;
    }

    if (BCryptGetProperty(
        impl->alg,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&impl->objectSize),
        sizeof(impl->objectSize),
        &resultSize,
        0) < 0)
    {
        m_lastError = "Cannot query SHA-256 parameters";
        return false;
    }

    impl->object.resize(impl->objectSize);
    impl->buffer.resize(kReadBufferSize);

    auto detector = std::make_unique<HashDetector>();

    if (!detector->loadDatabase(databasePath))
    {
        m_lastError =
            "Cannot read hash database: "
            + WideToUtf8(databasePath.wstring())
            + " (missing, empty or locked)";

        return false;
    }

    // An empty list is valid to open but useless for scanning.
    if (detector->size() == 0)
    {
        m_lastError =
            "Hash database contains no hashes: "
            + WideToUtf8(databasePath.wstring());

        return false;
    }

    if (!cachePath.empty())
    {
        impl->cachePath = cachePath;

        impl->cache.load(
            cachePath,
            kEngineVersion);
    }

    // YARA is an addition, not a prerequisite: if the rules cannot be
    // compiled the scanner still hashes and runs PE heuristics.
    impl->yaraRulesPath = YaraRulesDirectory();

    if (!InitializeYara()
        || !CompileYaraRules(
            impl->yaraRulesPath,
            &impl->yaraRules))
    {
        impl->yaraRules = nullptr;

        OutputDebugStringW(
            L"[BladeAntivirus] YARA disabled: rules were not loaded. "
            L"Hash and heuristic detection keep working.\n");
    }

    impl_ = std::move(impl);
    detector_ = std::move(detector);

    return true;
}

const std::string& Scanner::lastError() const
{
    return m_lastError;
}

bool Scanner::hasYaraRules() const
{
    return impl_ && impl_->yaraRules != nullptr;
}

void Scanner::saveCache()
{
    if (impl_
        && !impl_->cachePath.empty()
        && impl_->cache.dirty())
    {
        impl_->cache.save(
            impl_->cachePath,
            kEngineVersion);
    }
}

std::size_t Scanner::databaseSize() const
{
    return detector_ ? detector_->size() : 0;
}

ScanResult Scanner::scan(
    const std::filesystem::path& filePath)
{
    return scan(filePath, ScanLimits{});
}

ScanResult Scanner::scan(
    const std::filesystem::path& filePath,
    const ScanLimits& limits)
{
    ScanResult result;

    result.file = filePath.wstring();

    if (!impl_ || !detector_)
    {
        return Error(
            std::move(result),
            ERROR_NOT_READY);
    }

    const std::wstring path =
        ToWin32Path(filePath);

    WIN32_FILE_ATTRIBUTE_DATA attributes{};

    if (!GetFileAttributesExW(
        path.c_str(),
        GetFileExInfoStandard,
        &attributes))
    {
        return Error(
            std::move(result),
            GetLastError());
    }

    if (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        return Error(
            std::move(result),
            ERROR_DIRECTORY);
    }

    const std::uint64_t size =
        (static_cast<std::uint64_t>(
            attributes.nFileSizeHigh) << 32)
        | attributes.nFileSizeLow;

    const std::uint64_t mtime =
        FileTimeToU64(attributes.ftLastWriteTime);

    if ((attributes.dwFileAttributes & kCloudMask)
        || size > limits.maxFileSize)
    {
        return Skipped(std::move(result));
    }

    ScanWithYara(
        impl_->yaraRules,
        filePath,
        result,
        limits.yaraTimeoutSeconds);

    if (size == 0)
    {
        result.sha256 = kEmptySha256;

        if (result.yaraMatch)
        {
            result.details = YaraDetails(result);
            result.verdict = "SUSPICIOUS";
        }
        else
        {
            result.verdict = "CLEAN";
        }

        return result;
    }

    // A YARA hit must be corroborated by PE analysis, so cached results are
    // only used when no rule matched.
    if (!result.yaraMatch)
    {
        HashDetector::Digest cached{};

        if (impl_->cache.find(
            filePath,
            size,
            mtime,
            cached))
        {
            std::array<UCHAR, 32> digest{};

            std::memcpy(
                digest.data(),
                cached.data(),
                digest.size());

            result.sha256 = ToHex(digest);

            result.hashMatch =
                detector_->contains(cached);

            result.verdict =
                result.hashMatch
                ? "MALICIOUS"
                : "CLEAN";

            return result;
        }
    }

    FileHandle file;

    file.h = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ
        | FILE_SHARE_WRITE
        | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);

    if (file.h == INVALID_HANDLE_VALUE)
    {
        return Error(
            std::move(result),
            GetLastError());
    }

    if (GetFileType(file.h) != FILE_TYPE_DISK)
        return Skipped(std::move(result));

    HashHandle hash;

    if (BCryptCreateHash(
        impl_->alg,
        &hash.h,
        impl_->object.data(),
        impl_->objectSize,
        nullptr,
        0,
        0) < 0)
    {
        hash.h = nullptr;

        return Error(
            std::move(result),
            ERROR_INVALID_FUNCTION);
    }

    bool first = true;
    bool collect = false;

    PeProbe peProbe = PeProbe::No;

    std::uint64_t peFarOffset = 0;

    for (;;)
    {
        DWORD bytesRead = 0;

        if (!ReadFile(
            file.h,
            impl_->buffer.data(),
            kReadBufferSize,
            &bytesRead,
            nullptr))
        {
            return Error(
                std::move(result),
                GetLastError());
        }

        if (bytesRead == 0)
            break;

        if (first)
        {
            peProbe = ProbePE(
                impl_->buffer.data(),
                bytesRead,
                peFarOffset);

            first = false;

            if (size <= limits.maxAnalyzeSize
                && bytesRead >= 2
                && impl_->buffer[0] == 'M'
                && impl_->buffer[1] == 'Z')
            {
                collect = true;

                impl_->image.clear();

                impl_->image.reserve(
                    static_cast<std::size_t>(size));
            }
        }

        if (collect)
        {
            if (impl_->image.size() + bytesRead
        > limits.maxAnalyzeSize)
            {
                collect = false;
                impl_->image.clear();
            }
            else
            {
                impl_->image.insert(
                    impl_->image.end(),
                    impl_->buffer.begin(),
                    impl_->buffer.begin() + bytesRead);
            }
        }

        if (BCryptHashData(
            hash.h,
            impl_->buffer.data(),
            bytesRead,
            0) < 0)
        {
            return Error(
                std::move(result),
                ERROR_INVALID_DATA);
        }
    }

    std::array<UCHAR, 32> digest{};

    if (BCryptFinishHash(
        hash.h,
        digest.data(),
        static_cast<ULONG>(digest.size()),
        0) < 0)
    {
        return Error(
            std::move(result),
            ERROR_INVALID_DATA);
    }

    result.sha256 = ToHex(digest);

    HashDetector::Digest key{};

    std::memcpy(
        key.data(),
        digest.data(),
        key.size());

    result.hashMatch =
        detector_->contains(key);

    // A hash-database hit is authoritative and needs no further analysis.
    if (result.hashMatch)
    {
        result.isPE =
            peProbe == PeProbe::Yes;

        result.verdict = "MALICIOUS";

        ApplyYaraVerdict(filePath, result);

        impl_->image.clear();

        return result;
    }

    // Structural PE analysis.
    // Malware family signatures are handled by YARA.

    bool heuristicsSuspicious = false;

    if (collect && !impl_->image.empty())
    {
        const blade::PeReport report =
            blade::analyzePe(
                impl_->image.data(),
                impl_->image.size());

        if (impl_->image.capacity() > (8u << 20))
            std::vector<UCHAR>().swap(impl_->image);
        else
            impl_->image.clear();

        if (report.valid)
        {
            result.isPE = true;
            result.heuristicScore = report.score;

            if (report.score >= blade::kSuspiciousThreshold
                && !IsTrustedSigned(filePath))
            {
                for (const std::string& reason : report.reasons)
                {
                    if (!result.details.empty())
                        result.details += "; ";

                    result.details += reason;
                }

                heuristicsSuspicious = true;
            }
        }
    }
    else
    {
        if (peProbe == PeProbe::Yes)
        {
            result.isPE = true;
        }
        else if (peProbe == PeProbe::Far
            && peFarOffset + sizeof(DWORD) <= size)
        {
            result.isPE =
                ReadPeSignatureAt(
                    file.h,
                    peFarOffset);
        }
    }

    if (result.yaraMatch)
    {
        // One rule from a hand-maintained ruleset is reported as suspicious
        // unless independent analysis agrees. Only the hash database or the
        // PE heuristics can promote a match to "malicious".
        const std::string yaraText = YaraDetails(result);

        if (result.details.empty())
            result.details = yaraText;
        else
            result.details = yaraText + "; " + result.details;

        if (heuristicsSuspicious)
        {
            result.verdict = "MALICIOUS";
        }
        else
        {
            result.verdict = "SUSPICIOUS";

            if (IsTrustedSigned(filePath))
                result.details += " (digitally signed file, possible false positive)";
            else
                result.details += " (no corroborating PE heuristics)";
        }

        return result;
    }

    if (heuristicsSuspicious)
    {
        result.verdict = "SUSPICIOUS";

        return result;
    }

    result.verdict = "CLEAN";

    impl_->cache.add(
        filePath,
        size,
        mtime,
        key);

    return result;
}
