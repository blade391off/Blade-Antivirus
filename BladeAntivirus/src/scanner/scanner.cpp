#include "scanner.h"
#include "hash_detector.h"

#include <windows.h>
#include <bcrypt.h>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

Scanner::Scanner()
{
    detector = nullptr;
}

Scanner::~Scanner()
{
    delete detector;
    detector = nullptr;
}

bool Scanner::initialize(
    const std::string& databasePath
)
{
    delete detector;

    detector = new HashDetector();

    return detector->loadDatabase(
        databasePath
    );
}

std::string Scanner::calculateSHA256(
    const std::string& filePath
)
{
    std::ifstream file(
        filePath,
        std::ios::binary
    );

    if (!file.is_open())
        return {};

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    DWORD objectSize = 0;
    DWORD dataSize = 0;

    if (BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0
    ) != 0)
    {
        return {};
    }

    if (BCryptGetProperty(
        algorithm,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&objectSize),
        sizeof(objectSize),
        &dataSize,
        0
    ) != 0)
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return {};
    }

    std::vector<UCHAR> hashObject(
        objectSize
    );

    if (BCryptCreateHash(
        algorithm,
        &hash,
        hashObject.data(),
        objectSize,
        nullptr,
        0,
        0
    ) != 0)
    {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return {};
    }

    std::vector<char> buffer(
        1024 * 1024
    );

    while (file)
    {
        file.read(
            buffer.data(),
            static_cast<std::streamsize>(
                buffer.size()
                )
        );

        std::streamsize bytesRead =
            file.gcount();

        if (bytesRead > 0)
        {
            if (BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(
                    buffer.data()
                    ),
                static_cast<ULONG>(
                    bytesRead
                    ),
                0
            ) != 0)
            {
                BCryptDestroyHash(hash);
                BCryptCloseAlgorithmProvider(
                    algorithm,
                    0
                );

                return {};
            }
        }
    }

    DWORD hashSize = 0;

    if (BCryptGetProperty(
        algorithm,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashSize),
        sizeof(hashSize),
        &dataSize,
        0
    ) != 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return {};
    }

    std::vector<UCHAR> digest(
        hashSize
    );

    if (BCryptFinishHash(
        hash,
        digest.data(),
        hashSize,
        0
    ) != 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return {};
    }

    BCryptDestroyHash(hash);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    std::ostringstream result;

    result << std::hex
        << std::setfill('0');

    for (UCHAR byte : digest)
    {
        result
            << std::setw(2)
            << static_cast<int>(byte);
    }

    return result.str();
}

bool Scanner::checkPE(
    const std::string& filePath
)
{
    std::ifstream file(
        filePath,
        std::ios::binary
    );

    if (!file.is_open())
        return false;

    IMAGE_DOS_HEADER dosHeader{};

    file.read(
        reinterpret_cast<char*>(
            &dosHeader
            ),
        sizeof(dosHeader)
    );

    if (!file)
        return false;

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if (dosHeader.e_lfanew <= 0)
        return false;

    file.seekg(
        dosHeader.e_lfanew,
        std::ios::beg
    );

    DWORD signature = 0;

    file.read(
        reinterpret_cast<char*>(
            &signature
            ),
        sizeof(signature)
    );

    if (!file)
        return false;

    return signature ==
        IMAGE_NT_SIGNATURE;
}

ScanResult Scanner::scan(
    const std::string& filePath
)
{
    ScanResult result;

    result.file =
        filePath;

    result.sha256 =
        calculateSHA256(
            filePath
        );

    if (result.sha256.empty())
    {
        result.verdict =
            "ERROR";

        return result;
    }

    result.isPE =
        checkPE(
            filePath
        );

    if (detector)
    {
        result.hashMatch =
            detector->contains(
                result.sha256
            );
    }

    if (result.hashMatch)
    {
        result.verdict =
            "MALICIOUS";
    }
    else
    {
        result.verdict =
            "CLEAN";
    }

    return result;
}
