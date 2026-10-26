#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "scanner.h"
#include "hash_detector.h"

#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <cstring>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// Older SDKs do not define the cloud-recall attributes.
#ifndef FILE_ATTRIBUTE_RECALL_ON_OPEN
#define FILE_ATTRIBUTE_RECALL_ON_OPEN 0x00040000
#endif
#ifndef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
#define FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS 0x00400000
#endif

namespace
{
    constexpr DWORD kReadBufferSize = 256 * 1024;

    // Opening these would make Windows download the file from the cloud.
    constexpr DWORD kCloudMask =
        FILE_ATTRIBUTE_OFFLINE
        | FILE_ATTRIBUTE_RECALL_ON_OPEN
        | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;

    // SHA-256 of an empty file.
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

    // PE detection works on the first buffer. If the PE header lies further
    // into the file (e_lfanew beyond the buffer) the caller reads it directly.
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
}

struct Scanner::Impl
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    DWORD objectSize = 0;
    std::vector<UCHAR> object;
    std::vector<UCHAR> buffer;

    ~Impl()
    {
        if (alg)
            BCryptCloseAlgorithmProvider(alg, 0);
    }
};

Scanner::Scanner() = default;
Scanner::~Scanner() = default;

bool Scanner::initialize(const std::filesystem::path& databasePath)
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

    // Commit only when everything succeeded.
    impl_ = std::move(impl);
    detector_ = std::move(detector);

    return true;
}

std::size_t Scanner::databaseSize() const
{
    return detector_ ? detector_->size() : 0;
}

ScanResult Scanner::scan(const std::filesystem::path& filePath)
{
    ScanResult result;
    result.file = filePath.wstring();

    // Fail loudly: never report CLEAN without a loaded database.
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

    if ((attributes.dwFileAttributes & kCloudMask) || size > kMaxFileSize)
        return Skipped(std::move(result));

    // An empty file cannot be malware and needs no open/hash.
    if (size == 0)
    {
        result.sha256 = kEmptySha256;
        result.verdict = "CLEAN";
        return result;
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
    PeProbe peProbe = PeProbe::No;
    std::uint64_t peFarOffset = 0;

    for (;;)
    {
        DWORD bytesRead = 0;

        // A failed read must be an ERROR, not a silently truncated hash.
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

    // Hashing is done, so the file pointer may move now.
    if (peProbe == PeProbe::Yes)
        result.isPE = true;
    else if (peProbe == PeProbe::Far && peFarOffset + sizeof(DWORD) <= size)
        result.isPE = ReadPeSignatureAt(file.h, peFarOffset);

    result.sha256 = ToHex(digest);

    HashDetector::Digest key{};
    std::memcpy(key.data(), digest.data(), key.size());

    result.hashMatch = detector_->contains(key);
    result.verdict = result.hashMatch ? "MALICIOUS" : "CLEAN";

    return result;
}
