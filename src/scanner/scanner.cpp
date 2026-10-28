#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "scanner.h"
#include "hash_detector.h"
#include "scanner/pe_analyzer.h"
#include "scanner/scan_cache.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>

#include <array>
#include <cstring>
#include <vector>

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
    constexpr DWORD kReadBufferSize = 256 * 1024;

    
    constexpr DWORD kCloudMask =
        FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    
    constexpr char kEmptySha256[] =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    struct FileHandle
    {
        HANDLE h = INVALID_HANDLE_VALUE;
        ~FileHandle() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    };

    struct HashHandle
    {
        BCRYPT_HASH_HANDLE h = nullptr;
        ~HashHandle() { if (h) BCryptDestroyHash(h); }
    };

    // Adds \\?\ so paths longer than MAX_PATH work.
    std::wstring ToWin32Path(const std::filesystem::path& input)
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

    
    enum class PeProbe { No, Yes, Far };

    PeProbe ProbePE(const UCHAR* data, std::size_t size, std::uint64_t& farOffset)
    {
        if (size < sizeof(IMAGE_DOS_HEADER))
            return PeProbe::No;

        IMAGE_DOS_HEADER dos{};
        std::memcpy(&dos, data, sizeof(dos));

        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0)
            return PeProbe::No;

        const std::size_t offset = static_cast<std::size_t>(dos.e_lfanew);

        if (offset > size || size - offset < sizeof(DWORD))
        {
            farOffset = static_cast<std::uint64_t>(dos.e_lfanew);
            return PeProbe::Far;
        }

        DWORD signature = 0;
        std::memcpy(&signature, data + offset, sizeof(signature));

        return signature == IMAGE_NT_SIGNATURE ? PeProbe::Yes : PeProbe::No;
    }

    bool ReadPeSignatureAt(HANDLE file, std::uint64_t offset)
    {
        LARGE_INTEGER position;
        position.QuadPart = static_cast<LONGLONG>(offset);

        if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
            return false;

        DWORD signature = 0;
        DWORD bytesRead = 0;

        return ReadFile(file, &signature, sizeof(signature), &bytesRead, nullptr)
            && bytesRead == sizeof(signature)
            && signature == IMAGE_NT_SIGNATURE;
    }

    std::string ToHex(const std::array<UCHAR, 32>& digest)
    {
        static const char kDigits[] = "0123456789abcdef";

        std::string out(64, '0');

        for (std::size_t i = 0; i < digest.size(); ++i)
        {
            out[2 * i] = kDigits[digest[i] >> 4];
            out[2 * i + 1] = kDigits[digest[i] & 0x0F];
        }

        return out;
    }

    ScanResult Error(ScanResult result, DWORD code)
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
        const HWND noUi = reinterpret_cast<HWND>(INVALID_HANDLE_VALUE);

        data.cbStruct = sizeof(data);
        data.dwUIChoice = WTD_UI_NONE;
        data.fdwRevocationChecks = WTD_REVOKE_NONE;
        data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
        data.dwStateAction = WTD_STATEACTION_VERIFY;

        const LONG status = WinVerifyTrust(noUi, &action, &data);

        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(noUi, &action, &data);

        return status == ERROR_SUCCESS;
    }

    bool VerifyEmbeddedSignature(const std::wstring& path)
    {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = path.c_str();

        WINTRUST_DATA data{};
        data.dwUnionChoice = WTD_CHOICE_FILE;
        data.pFile = &fileInfo;

        return RunWinVerifyTrust(data);
    }

    // windows system files are usually signed through security catalogs
    
    bool VerifyCatalogSignature(const std::wstring& path)
    {
        FileHandle file;
        file.h = CreateFileW(
            path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (file.h == INVALID_HANDLE_VALUE)
            return false;

        HCATADMIN admin = nullptr;

        if (!CryptCATAdminAcquireContext(&admin, nullptr, 0))
            return false;

        bool trusted = false;
        DWORD hashSize = 0;

        CryptCATAdminCalcHashFromFileHandle(file.h, &hashSize, nullptr, 0);

        if (hashSize > 0 && hashSize <= 64)
        {
            std::vector<BYTE> hash(hashSize);

            if (CryptCATAdminCalcHashFromFileHandle(
                    file.h, &hashSize, hash.data(), 0))
            {
                HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(
                    admin, hash.data(), hashSize, 0, nullptr);

                if (catalog)
                {
                    CATALOG_INFO info{};
                    info.cbStruct = sizeof(info);

                    if (CryptCATCatalogInfoFromContext(catalog, &info, 0))
                    {
                        static const wchar_t kHex[] = L"0123456789ABCDEF";
                        std::wstring tag;

                        for (DWORD i = 0; i < hashSize; ++i)
                        {
                            tag.push_back(kHex[hash[i] >> 4]);
                            tag.push_back(kHex[hash[i] & 0x0F]);
                        }

                        WINTRUST_CATALOG_INFO catalogInfo{};
                        catalogInfo.cbStruct = sizeof(catalogInfo);
                        catalogInfo.pcwszCatalogFilePath = info.wszCatalogFile;
                        catalogInfo.pcwszMemberTag = tag.c_str();
                        catalogInfo.pcwszMemberFilePath = path.c_str();
                        catalogInfo.hMemberFile = file.h;
                        catalogInfo.pbCalculatedFileHash = hash.data();
                        catalogInfo.cbCalculatedFileHash = hashSize;
                        catalogInfo.hCatAdmin = admin;

                        WINTRUST_DATA data{};
                        data.dwUnionChoice = WTD_CHOICE_CATALOG;
                        data.pCatalog = &catalogInfo;

                        trusted = RunWinVerifyTrust(data);
                    }

                    CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                }
            }
        }

        CryptCATAdminReleaseContext(admin, 0);
        return trusted;
    }

   
    bool IsTrustedSigned(const std::filesystem::path& filePath)
    {
        std::filesystem::path p = filePath;
        const std::wstring path = p.make_preferred().wstring();

        return VerifyEmbeddedSignature(path) || VerifyCatalogSignature(path);
    }

    std::uint64_t FileTimeToU64(const FILETIME& ft)
    {
        return (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32)
            | ft.dwLowDateTime;
    }
}

struct Scanner::Impl
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    DWORD objectSize = 0;
    std::vector<UCHAR> object;
    std::vector<UCHAR> buffer;
	std::vector<UCHAR> image; // pe file held in memory for analysis

    blade::ScanCache cache;
    std::filesystem::path cachePath;

    ~Impl()
    {
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
    auto impl = std::make_unique<Impl>();
    DWORD resultSize = 0;

    if (BCryptOpenAlgorithmProvider(
            &impl->alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
    {
        impl->alg = nullptr;
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
        return false;
    }

    impl->object.resize(impl->objectSize);
    impl->buffer.resize(kReadBufferSize);

    auto detector = std::make_unique<HashDetector>();

    if (!detector->loadDatabase(databasePath))
        return false;

    if (!cachePath.empty())
    {
        impl->cachePath = cachePath;
        impl->cache.load(cachePath, kEngineVersion);
    }

    
    impl_ = std::move(impl);
    detector_ = std::move(detector);

    return true;
}

void Scanner::saveCache()
{
    if (impl_ && !impl_->cachePath.empty() && impl_->cache.dirty())
        impl_->cache.save(impl_->cachePath, kEngineVersion);
}

std::size_t Scanner::databaseSize() const
{
    return detector_ ? detector_->size() : 0;
}

ScanResult Scanner::scan(const std::filesystem::path& filePath)
{
    ScanResult result;
    result.file = filePath.wstring();

    
    if (!impl_ || !detector_)
        return Error(std::move(result), ERROR_NOT_READY);

    const std::wstring path = ToWin32Path(filePath);

    WIN32_FILE_ATTRIBUTE_DATA attributes{};

    if (!GetFileAttributesExW(
            path.c_str(), GetFileExInfoStandard, &attributes))
    {
        return Error(std::move(result), GetLastError());
    }

    if (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        return Error(std::move(result), ERROR_DIRECTORY);

    const std::uint64_t size =
        (static_cast<std::uint64_t>(attributes.nFileSizeHigh) << 32)
        | attributes.nFileSizeLow;
    const std::uint64_t mtime = FileTimeToU64(attributes.ftLastWriteTime);

    if ((attributes.dwFileAttributes & kCloudMask) || size > kMaxFileSize)
        return Skipped(std::move(result));

    
    if (size == 0)
    {
        result.sha256 = kEmptySha256;
        result.verdict = "CLEAN";
        return result;
    }

    
    {
        HashDetector::Digest cached{};

        if (impl_->cache.find(filePath, size, mtime, cached))
        {
            std::array<UCHAR, 32> digest{};
            std::memcpy(digest.data(), cached.data(), digest.size());

            result.sha256 = ToHex(digest);
            result.hashMatch = detector_->contains(cached);
            result.verdict = result.hashMatch ? "MALICIOUS" : "CLEAN";
            return result;
        }
    }

    FileHandle file;
    file.h = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);

    if (file.h == INVALID_HANDLE_VALUE)
        return Error(std::move(result), GetLastError());

    // Pipes, consoles and devices can block forever on read.
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
        return Error(std::move(result), ERROR_INVALID_FUNCTION);
    }

    bool first = true;
    bool collect = false; // keep the file in memory for PE analysis
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
            return Error(std::move(result), GetLastError());
        }

        if (bytesRead == 0)
            break;

        if (first)
        {
            peProbe = ProbePE(impl_->buffer.data(), bytesRead, peFarOffset);
            first = false;

            
            if (size <= kMaxAnalyzeSize && bytesRead >= 2
                && impl_->buffer[0] == 'M' && impl_->buffer[1] == 'Z')
            {
                collect = true;
                impl_->image.clear();
                impl_->image.reserve(static_cast<std::size_t>(size));
            }
        }

        if (collect)
        {
            if (impl_->image.size() + bytesRead > kMaxAnalyzeSize)
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
                hash.h, impl_->buffer.data(), bytesRead, 0) < 0)
        {
            return Error(std::move(result), ERROR_INVALID_DATA);
        }
    }

    std::array<UCHAR, 32> digest{};

    if (BCryptFinishHash(
            hash.h, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    {
        return Error(std::move(result), ERROR_INVALID_DATA);
    }

    result.sha256 = ToHex(digest);

    HashDetector::Digest key{};
    std::memcpy(key.data(), digest.data(), key.size());

    // 2. Blocklist.
    result.hashMatch = detector_->contains(key);

    if (result.hashMatch)
    {
        result.isPE = peProbe == PeProbe::Yes;
        result.verdict = "MALICIOUS";
        impl_->image.clear();
        return result;
    }

    // 3 + 4. Static PE heuristics, softened by a valid signature.
    if (collect && !impl_->image.empty())
    {
        const blade::PeReport report =
            blade::analyzePe(impl_->image.data(), impl_->image.size());

        // Release big buffers so a scan does not pin 32 MB for its lifetime.
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

                result.verdict = "SUSPICIOUS";
                return result; // never cached: re-evaluated every scan
            }
        }
    }
    else
    {
        // Too big for full analysis (or not a PE): cheap header probe only.
        if (peProbe == PeProbe::Yes)
            result.isPE = true;
        else if (peProbe == PeProbe::Far && peFarOffset + sizeof(DWORD) <= size)
            result.isPE = ReadPeSignatureAt(file.h, peFarOffset);
    }

    result.verdict = "CLEAN";
    impl_->cache.add(filePath, size, mtime, key);

    return result;
}
