#include "strings.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <string>

static void addStringSign(
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

void analyzeStringSigns(
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
        const char* name;
        int score;
        const char* description;
    };

    static const StringSign signs[] =
    {
        {
            "powershell -enc",
            "POWERSHELL_ENCODED",
            10,
            "Encoded PowerShell command reference"
        },
        {
            "frombase64string",
            "POWERSHELL_BASE64",
            10,
            "PowerShell Base64 decoding reference"
        },
        {
            "cmd.exe /c",
            "CMD_EXECUTION",
            5,
            "Command shell execution reference"
        },
        {
            "rundll32.exe",
            "RUNDLL32_REFERENCE",
            5,
            "Rundll32 execution reference"
        },
        {
            "regsvr32.exe",
            "REGSVR32_REFERENCE",
            5,
            "Regsvr32 execution reference"
        }
    };

    for (const auto& sign : signs)
    {
        if (data.find(sign.value) != std::string::npos)
        {
            addStringSign(
                result,
                sign.name,
                sign.score,
                sign.description
            );
        }
    }
}