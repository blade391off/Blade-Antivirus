#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "heuristic_detector.h"
#include <windows.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace
{
    void addFinding(
        HeuristicResult& result,
        int points,
        const std::string& description)
    {
        result.score = (std::min)(100, result.score + points);
        result.findings.push_back(description);
    }

    double calculateEntropy(const std::array<std::uint64_t, 256>& counts,
        std::uint64_t total)
    {
        if (total == 0)
            return 0.0;

        double entropy = 0.0;

        for (const auto count : counts)
        {
            if (count == 0)
                continue;

            const double probability =
                static_cast<double>(count) /
                static_cast<double>(total);

            entropy -= probability * std::log2(probability);
        }

        return entropy;
    }

    
    bool readExactWin32(HANDLE hFile, void* destination,
        std::size_t size, std::uint64_t offset)
    {
        LARGE_INTEGER liOffset;
        liOffset.QuadPart = offset;

        if (!SetFilePointerEx(hFile, liOffset, NULL, FILE_BEGIN))
            return false;

        DWORD bytesRead = 0;
        if (!ReadFile(hFile, destination, static_cast<DWORD>(size), &bytesRead, NULL))
            return false;

        return bytesRead == static_cast<DWORD>(size);
    }
}

HeuristicResult HeuristicDetector::analyze(
    const std::wstring& filePath) const
{
    HeuristicResult result;

    WIN32_FILE_ATTRIBUTE_DATA info{};

    if (!GetFileAttributesExW(
        filePath.c_str(),
        GetFileExInfoStandard,
        &info))
    {
        result.error = "Cannot read file attributes";
        return result;
    }

    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        result.error = "Path is a directory";
        return result;
    }

    const std::uint64_t fileSize =
        (static_cast<std::uint64_t>(info.nFileSizeHigh) << 32) |
        info.nFileSizeLow;

    if (fileSize == 0)
    {
        result.findings.emplace_back("Empty file");
        return result;
    }

    if (fileSize > MaxFileSize)
    {
        result.error = "File exceeds analysis size limit";
        return result;
    }

    
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        result.error = "Cannot open file";
        return result;
    }

    IMAGE_DOS_HEADER dos{};

    if (!readExactWin32(hFile, &dos, sizeof(dos), 0))
    {
        CloseHandle(hFile);
        result.findings.emplace_back("File is too small for a PE header");
        return result;
    }

    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
    {
        CloseHandle(hFile);
        result.findings.emplace_back("Not a Windows PE file");
        return result;
    }

    if (dos.e_lfanew <= 0)
    {
        CloseHandle(hFile);
        addFinding(result, 35, "Invalid PE header offset");
        return result;
    }

    const std::uint64_t ntOffset =
        static_cast<std::uint64_t>(dos.e_lfanew);

    DWORD signature = 0;

    if (!readExactWin32(hFile, &signature, sizeof(signature), ntOffset) ||
        signature != IMAGE_NT_SIGNATURE)
    {
        CloseHandle(hFile);
        addFinding(result, 35, "Invalid PE signature");
        return result;
    }

    IMAGE_FILE_HEADER header{};

    const std::uint64_t headerOffset =
        ntOffset + sizeof(DWORD);

    if (!readExactWin32(hFile, &header, sizeof(header), headerOffset))
    {
        CloseHandle(hFile);
        addFinding(result, 30, "Truncated PE file header");
        return result;
    }

    if (header.NumberOfSections == 0 ||
        header.NumberOfSections > 96)
    {
        addFinding(result, 15, "Unusual PE section count");
    }

    const std::uint64_t optionalOffset =
        headerOffset + sizeof(IMAGE_FILE_HEADER);

    WORD magic = 0;

    if (!readExactWin32(hFile, &magic, sizeof(magic), optionalOffset) ||
        (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
            magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        CloseHandle(hFile);
        addFinding(result, 30, "Invalid PE optional header");
        return result;
    }

    if (optionalOffset > fileSize ||
        header.SizeOfOptionalHeader > fileSize - optionalOffset)
    {
        CloseHandle(hFile);
        addFinding(result, 30, "Truncated PE optional header");
        return result;
    }

    const std::uint64_t sectionOffset =
        optionalOffset + header.SizeOfOptionalHeader;

    if (sectionOffset > fileSize ||
        header.NumberOfSections >
        (fileSize - sectionOffset) / sizeof(IMAGE_SECTION_HEADER))
    {
        CloseHandle(hFile);
        addFinding(result, 30, "Truncated PE section table");
        return result;
    }

    result.isPE = true;

    bool writableExecutable = false;

    for (WORD i = 0; i < header.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section{};

        const std::uint64_t offset =
            sectionOffset +
            static_cast<std::uint64_t>(i) *
            sizeof(IMAGE_SECTION_HEADER);

        if (!readExactWin32(hFile, &section, sizeof(section), offset))
        {
            CloseHandle(hFile);
            addFinding(result, 30, "Cannot read PE section");
            return result;
        }

        const DWORD flags = section.Characteristics;

        if ((flags & IMAGE_SCN_MEM_EXECUTE) &&
            (flags & IMAGE_SCN_MEM_WRITE))
        {
            writableExecutable = true;
        }

        char name[9]{};
        std::memcpy(name, section.Name, 8);
        const std::string sectionName(name);

        if (sectionName == "UPX0" ||
            sectionName == "UPX1" ||
            sectionName == ".aspack" ||
            sectionName == ".packed")
        {
            addFinding(result, 8,
                "Section name resembles a common packer marker");
        }
    }

    if (writableExecutable)
    {
        addFinding(result, 25,
            "PE has a writable and executable section");
    }

    std::array<std::uint64_t, 256> counts{};
    std::array<char, 65536> buffer{};
    std::uint64_t remaining = fileSize;

    LARGE_INTEGER liZero;
    liZero.QuadPart = 0;
    SetFilePointerEx(hFile, liZero, NULL, FILE_BEGIN);

    while (remaining > 0)
    {
        const auto chunk = static_cast<DWORD>(
            (std::min)(remaining,
                static_cast<std::uint64_t>(buffer.size())));

        DWORD bytesRead = 0;
        if (!ReadFile(hFile, buffer.data(), chunk, &bytesRead, NULL) || bytesRead != chunk)
        {
            CloseHandle(hFile);
            result.error = "Failed while reading file";
            return result;
        }

        for (DWORD i = 0; i < chunk; ++i)
        {
            const auto byte =
                static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)]);
            ++counts[byte];
        }

        remaining -= static_cast<std::uint64_t>(chunk);
    }

    CloseHandle(hFile); 

    if (calculateEntropy(counts, fileSize) >= 7.2)
    {
        addFinding(result, 12,
            "High file entropy; packing or encryption is possible");
    }

    if (result.findings.empty())
        result.findings.emplace_back("No heuristic indicators found");

    return result;
}
