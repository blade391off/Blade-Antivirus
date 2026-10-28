#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace blade
{
    // Score at or above which a PE file is reported as SUSPICIOUS.
    constexpr int kSuspiciousThreshold = 60;

    struct PeSectionInfo
    {
        std::string name;
        std::uint32_t virtualSize = 0;
        std::uint32_t virtualAddress = 0;
        std::uint32_t rawSize = 0;
        std::uint32_t rawOffset = 0;
        std::uint32_t characteristics = 0;
        double entropy = 0.0; // of the raw data (0 when empty / outside the file)

        bool executable() const { return (characteristics & 0x20000000u) != 0; }
        bool writable() const { return (characteristics & 0x80000000u) != 0; }
    };

    struct PeReport
    {
        bool valid = false;               // parsed as a PE image
        bool is64 = false;
        bool isDll = false;
        bool isDotNet = false;
        bool hasEmbeddedSignature = false; // certificate table present (NOT verified here)
        std::uint16_t machine = 0;
        std::uint32_t entryPointRva = 0;
        std::size_t importFunctionCount = 0;
        std::vector<PeSectionInfo> sections;

        int score = 0;                     // sum of finding weights
        std::vector<std::string> reasons;  // strongest first, at most 6
    };

    // Static, bounds-checked analysis of a PE image held in memory.
    // Never reads outside [data, data + size); no recursion, all loops bounded.
    // Assumes a little-endian host (Windows x86/x64/ARM64).
    PeReport analyzePe(const std::uint8_t* data, std::size_t size);

    double shannonEntropy(const std::uint8_t* data, std::size_t size);
}
