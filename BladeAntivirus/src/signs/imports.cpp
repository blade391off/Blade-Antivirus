#include "import_signs.hpp"

#include <windows.h>

#include <fstream>
#include <string>

static void addImportSign(
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

static bool containsBytes(
    const std::string& data,
    const std::string& value
)
{
    return data.find(value) != std::string::npos;
}

void analyzeImportSigns(
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

    struct ImportSign
    {
        const char* value;
        const char* name;
        int score;
        const char* description;
    };

    static const ImportSign signs[] =
    {
        {
            "VirtualAlloc",
            "IMPORT_VIRTUALALLOC",
            3,
            "Virtual memory allocation API reference"
        },
        {
            "VirtualProtect",
            "IMPORT_VIRTUALPROTECT",
            3,
            "Memory protection modification API reference"
        },
        {
            "WriteProcessMemory",
            "IMPORT_WRITEPROCESSMEMORY",
            5,
            "Process memory writing API reference"
        },
        {
            "CreateRemoteThread",
            "IMPORT_CREATEREMOTETHREAD",
            7,
            "Remote thread creation API reference"
        },
        {
            "WinExec",
            "IMPORT_WINEXEC",
            3,
            "Legacy process execution API reference"
        }
    };

    for (const auto& sign : signs)
    {
        if (containsBytes(data, sign.value))
        {
            addImportSign(
                result,
                sign.name,
                sign.score,
                sign.description
            );
        }
    }
}