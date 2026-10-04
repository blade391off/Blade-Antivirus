#include "pe_signs.hpp"

#include <windows.h>

#include <fstream>

static void addPESign(
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

void analyzePESigns(
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

    IMAGE_DOS_HEADER dos{};

    file.read(
        reinterpret_cast<char*>(&dos),
        sizeof(dos)
    );

    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE)
        return;

    file.seekg(
        dos.e_lfanew,
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
        addPESign(
            result,
            "PE_NO_SECTIONS",
            20,
            "PE file contains no sections"
        );

        return;
    }

    if (fileHeader.NumberOfSections > 20)
    {
        addPESign(
            result,
            "PE_MANY_SECTIONS",
            5,
            "PE file contains many sections"
        );
    }

    if (!(fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    {
        addPESign(
            result,
            "PE_NOT_EXECUTABLE",
            5,
            "PE executable characteristic is missing"
        );
    }

    if (fileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        addPESign(
            result,
            "PE_DLL",
            0,
            "File is a DLL"
        );
    }
}