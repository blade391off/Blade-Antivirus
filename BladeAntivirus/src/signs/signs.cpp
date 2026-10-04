#include "signs.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <string>

bool SignsEngine::isPE(const std::string& filePath)
{
    std::ifstream file(
        filePath,
        std::ios::binary
    );

    if (!file.is_open())
        return false;

    IMAGE_DOS_HEADER dosHeader{};

    file.read(
        reinterpret_cast<char*>(&dosHeader),
        sizeof(dosHeader)
    );

    if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    if (dosHeader.e_lfanew <= 0)
        return false;

    file.seekg(
        dosHeader.e_lfanew,
        std::ios::beg
    );

    DWORD signature = 0;

    file.read(
        reinterpret_cast<char*>(&signature),
        sizeof(signature)
    );

    return file &&
        signature == IMAGE_NT_SIGNATURE;
}

void SignsEngine::addSign(
    SignsResult& result,
    const std::string& name,
    int score,
    const std::string& description
)
{
    result.score += score;

    result.matches.push_back({
        name,
        score,
        description
        });
}

void SignsEngine::analyzePE(
    const std::string& filePath,
    SignsResult& result
)
{
    std::ifstream file(
        filePath,
        std::ios::binary
    );

    if (!file.is_open())
        return;

    IMAGE_DOS_HEADER dosHeader{};

    file.read(
        reinterpret_cast<char*>(&dosHeader),
        sizeof(dosHeader)
    );

    if (!file || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return;

    if (dosHeader.e_lfanew <= 0)
        return;

    file.seekg(
        dosHeader.e_lfanew,
        std::ios::beg
    );

    DWORD signature = 0;

    file.read(
        reinterpret_cast<char*>(&signature),
        sizeof(signature)
    );

    if (!file || signature != IMAGE_NT_SIGNATURE)
        return;

    IMAGE_FILE_HEADER fileHeader{};

    file.read(
        reinterpret_cast<char*>(&fileHeader),
        sizeof(fileHeader)
    );

    if (!file)
        return;

    if (fileHeader.NumberOfSections == 0)
    {
        addSign(
            result,
            "PE_NO_SECTIONS",
            20,
            "PE file contains no sections"
        );
    }

    if (fileHeader.NumberOfSections > 20)
    {
        addSign(
            result,
            "PE_MANY_SECTIONS",
            5,
            "PE file contains an unusually large number of sections"
        );
    }

    if (!(fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        addSign(
            result,
            "PE_NOT_EXECUTABLE",
            5,
            "PE image is missing executable characteristic"
        );
    }
}

void SignsEngine::analyzeStrings(
    const std::string& filePath,
    SignsResult& result
)
{
    std::ifstream file(
        filePath,
        std::ios::binary
    );

    if (!file.is_open())
        return;

    std::string data(
        std::istreambuf_iterator<char>(file),
        {}
    );

    std::transform(
        data.begin(),
        data.end(),
        data.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                std::tolower(c)
                );
        }
    );

    struct StringSign
    {
        const char* value;
        int score;
        const char* name;
        const char* description;
    };

    static const StringSign signs[] =
    {
        {
            "powershell -enc",
            10,
            "POWERSHELL_ENCODED",
            "Encoded PowerShell command reference"
        },
        {
            "frombase64string",
            10,
            "POWERSHELL_BASE64",
            "PowerShell Base64 decoding reference"
        },
        {
            "cmd.exe /c",
            5,
            "CMD_EXECUTION",
            "Command shell execution reference"
        },
        {
            "rundll32.exe",
            5,
            "RUNDLL32_REFERENCE",
            "Rundll32 execution reference"
        },
        {
            "regsvr32.exe",
            5,
            "REGSVR32_REFERENCE",
            "Regsvr32 execution reference"
        }
    };

    for (const auto& sign : signs)
    {
        if (data.find(sign.value) != std::string::npos)
        {
            addSign(
                result,
                sign.name,
                sign.score,
                sign.description
            );
        }
    }
}

SignsResult SignsEngine::analyze(
    const std::string& filePath
)
{
    SignsResult result;

    if (!isPE(filePath))
    {
        result.verdict = "NOT_PE";
        return result;
    }

    analyzePE(
        filePath,
        result
    );

    analyzeStrings(
        filePath,
        result
    );

    if (result.score >= 50)
    {
        result.verdict = "MALICIOUS";
    }
    else if (result.score >= 20)
    {
        result.verdict = "SUSPICIOUS";
    }
    else
    {
        result.verdict = "CLEAN";
    }

    return result;
}