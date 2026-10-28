#include "pe_analyzer.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <functional>
#include <unordered_set>

namespace blade
{
namespace
{
    constexpr std::size_t kMaxSections = 96;
    constexpr std::size_t kMaxImportDlls = 512;
    constexpr std::size_t kMaxThunksPerDll = 4096;
    constexpr std::size_t kMaxEntropyBytes = 4u * 1024u * 1024u;
    constexpr std::size_t kStringScanFullLimit = 4u * 1024u * 1024u;
    constexpr std::size_t kStringScanMaxBytes = 16u * 1024u * 1024u;

    template <typename T>
    bool rd(const std::uint8_t* d, std::size_t n, std::size_t off, T& out)
    {
        if (off > n || n - off < sizeof(T))
            return false;

        std::memcpy(&out, d + off, sizeof(T));
        return true;
    }

    struct Finding
    {
        int weight;
        std::string text;
    };

    char lower(char c)
    {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    }

    std::string lowerCopy(std::string s)
    {
        for (char& c : s)
            c = lower(c);
        return s;
    }

    // Reads a NUL-terminated printable ASCII string (max `limit` chars).
    bool readCString(const std::uint8_t* d, std::size_t n, std::size_t off,
                     std::size_t limit, std::string& out)
    {
        out.clear();

        for (std::size_t i = 0; i < limit; ++i)
        {
            std::uint8_t c = 0;

            if (!rd(d, n, off + i, c))
                return false;

            if (c == 0)
                return !out.empty();

            if (c < 0x20 || c > 0x7E)
                return false;

            out.push_back(static_cast<char>(c));
        }

        return false; // too long
    }

    struct Rva
    {
        const std::vector<PeSectionInfo>* sections;
        std::uint32_t firstSectionVa;
        std::size_t fileSize;

        bool toOffset(std::uint32_t rva, std::size_t& off) const
        {
            if (rva < firstSectionVa) // inside the headers
            {
                off = rva;
                return off < fileSize;
            }

            for (const PeSectionInfo& s : *sections)
            {
                if (rva >= s.virtualAddress
                    && rva - s.virtualAddress < s.rawSize)
                {
                    const std::size_t o =
                        static_cast<std::size_t>(s.rawOffset)
                        + (rva - s.virtualAddress);

                    if (o < fileSize)
                    {
                        off = o;
                        return true;
                    }
                }
            }

            return false;
        }
    };

    bool isKnownPackerSection(const std::string& name, std::string& label)
    {
        static const char* const kNames[] = {
            "upx0", "upx1", "upx2", ".aspack", ".adata", ".themida",
            ".vmp0", ".vmp1", ".vmp2", ".enigma1", ".enigma2", ".petite",
            ".nsp0", ".nsp1", ".mpress1", ".mpress2", ".packed", ".yp",
            ".perplex", "pec1", "pec2", ".rmnet", ".boom", ".svkp"
        };

        const std::string n = lowerCopy(name);

        for (const char* candidate : kNames)
        {
            if (n == candidate)
            {
                label = name;
                return true;
            }
        }

        return false;
    }

    bool contains(const std::vector<std::uint8_t>& hay, const std::string& needle)
    {
        if (needle.empty() || hay.size() < needle.size())
            return false;

        const char* begin = reinterpret_cast<const char*>(hay.data());
        const char* end = begin + hay.size();

        return std::search(
                   begin, end,
                   std::boyer_moore_horspool_searcher<const char*>(
                       needle.data(), needle.data() + needle.size()))
            != end;
    }

    std::string toUtf16le(const std::string& ascii)
    {
        std::string out;
        out.reserve(ascii.size() * 2);

        for (char c : ascii)
        {
            out.push_back(c);
            out.push_back('\0');
        }

        return out;
    }
}

double shannonEntropy(const std::uint8_t* data, std::size_t size)
{
    if (size == 0)
        return 0.0;

    std::size_t histogram[256] = {};

    for (std::size_t i = 0; i < size; ++i)
        ++histogram[data[i]];

    double entropy = 0.0;
    const double total = static_cast<double>(size);

    for (std::size_t count : histogram)
    {
        if (count == 0)
            continue;

        const double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

PeReport analyzePe(const std::uint8_t* data, std::size_t size)
{
    PeReport report;
    std::vector<Finding> findings;

    const auto add = [&findings](int weight, std::string text) {
        findings.push_back({ weight, std::move(text) });
    };

    // ---- headers --------------------------------------------------------
    std::uint16_t mz = 0;
    std::uint32_t lfanew = 0;

    if (!rd(data, size, 0, mz) || mz != 0x5A4D || !rd(data, size, 0x3C, lfanew))
        return report;

    std::uint32_t signature = 0;

    if (!rd(data, size, lfanew, signature) || signature != 0x00004550u)
        return report;

    const std::size_t coff = static_cast<std::size_t>(lfanew) + 4;

    std::uint16_t machine = 0, numSections = 0, optSize = 0, fileChars = 0;

    if (!rd(data, size, coff, machine)
        || !rd(data, size, coff + 2, numSections)
        || !rd(data, size, coff + 16, optSize)
        || !rd(data, size, coff + 18, fileChars))
    {
        return report;
    }

    const std::size_t opt = coff + 20;
    std::uint16_t magic = 0;

    if (!rd(data, size, opt, magic) || (magic != 0x10B && magic != 0x20B))
        return report;

    report.is64 = magic == 0x20B;

    const std::size_t minOpt = report.is64 ? 112 : 96;

    if (optSize < minOpt)
        return report;

    std::uint32_t entry = 0, numDirs = 0;

    if (!rd(data, size, opt + 16, entry)
        || !rd(data, size, opt + (report.is64 ? 108 : 92), numDirs))
    {
        return report;
    }

    struct Dir { std::uint32_t rva = 0, size = 0; };
    Dir dirs[16];

    numDirs = std::min<std::uint32_t>(numDirs, 16);

    for (std::uint32_t i = 0; i < numDirs; ++i)
    {
        const std::size_t at = opt + minOpt + 8u * i;

        if (at + 8 > opt + optSize)
            break;

        rd(data, size, at, dirs[i].rva);
        rd(data, size, at + 4, dirs[i].size);
    }

    report.valid = true;
    report.machine = machine;
    report.entryPointRva = entry;
    report.isDll = (fileChars & 0x2000) != 0;
    report.isDotNet = dirs[14].rva != 0 && dirs[14].size != 0;
    report.hasEmbeddedSignature = dirs[4].size != 0;

    // ---- sections -------------------------------------------------------
    if (numSections > kMaxSections)
        add(20, "Abnormal number of sections");

    const std::size_t sectionTable = opt + optSize;
    const std::size_t sectionCount = std::min<std::size_t>(numSections, kMaxSections);
    bool unusualName = false;
    bool rawOutsideFile = false;
    bool truncatedTable = false;

    for (std::size_t i = 0; i < sectionCount; ++i)
    {
        const std::size_t at = sectionTable + 40 * i;
        char rawName[8] = {};

        if (at > size || size - at < 40)
        {
            truncatedTable = true;
            break;
        }

        std::memcpy(rawName, data + at, 8);

        PeSectionInfo s;

        for (int k = 0; k < 8 && rawName[k] != '\0'; ++k)
        {
            const unsigned char c = static_cast<unsigned char>(rawName[k]);

            if (c < 0x20 || c > 0x7E)
            {
                unusualName = true;
                s.name.push_back('?');
            }
            else
            {
                s.name.push_back(static_cast<char>(c));
            }
        }

        rd(data, size, at + 8, s.virtualSize);
        rd(data, size, at + 12, s.virtualAddress);
        rd(data, size, at + 16, s.rawSize);
        rd(data, size, at + 20, s.rawOffset);
        rd(data, size, at + 36, s.characteristics);

        if (s.rawSize > 0)
        {
            if (s.rawOffset > size || size - s.rawOffset < s.rawSize)
            {
                rawOutsideFile = true;
                s.rawSize = (s.rawOffset > size)
                    ? 0 : static_cast<std::uint32_t>(size - s.rawOffset);
            }

            if (s.rawSize > 0)
            {
                s.entropy = shannonEntropy(
                    data + s.rawOffset,
                    std::min<std::size_t>(s.rawSize, kMaxEntropyBytes));
            }
        }

        report.sections.push_back(std::move(s));
    }

    if (truncatedTable)
        add(20, "Section table is truncated");

    if (rawOutsideFile)
        add(20, "Section data lies outside the file");

    if (unusualName)
        add(10, "Unusual section names");

    if (report.sections.empty())
        add(25, "No sections");

    // entry point
    if (entry != 0 && !report.sections.empty())
    {
        const PeSectionInfo* entrySection = nullptr;
        std::size_t entryIndex = 0;

        for (std::size_t i = 0; i < report.sections.size(); ++i)
        {
            const PeSectionInfo& s = report.sections[i];
            const std::uint32_t span = std::max(s.virtualSize, s.rawSize);

            if (entry >= s.virtualAddress && entry - s.virtualAddress < span)
            {
                entrySection = &s;
                entryIndex = i;
                break;
            }
        }

        if (!entrySection)
            add(30, "Entry point lies outside every section");
        else if (!entrySection->executable())
            add(20, "Entry point is in a non-executable section");
        else if (entryIndex + 1 == report.sections.size() && report.sections.size() >= 3)
            add(10, "Entry point is in the last section");
    }

    bool wxReported = false, emptyExecReported = false,
         packedEntropyReported = false, packerNameReported = false;

    for (const PeSectionInfo& s : report.sections)
    {
        std::string label;

        if (!packerNameReported && isKnownPackerSection(s.name, label))
        {
            add(20, "Packer section name: " + label);
            packerNameReported = true;
        }

        if (s.executable() && s.writable() && !wxReported)
        {
            add(15, "Section is both writable and executable");
            wxReported = true;
        }

        if (s.executable() && s.rawSize == 0 && s.virtualSize >= 0x1000
            && !emptyExecReported)
        {
            add(20, "Executable section is empty on disk (unpacks at run time)");
            emptyExecReported = true;
        }

        if (s.executable() && s.rawSize >= 4096 && s.entropy > 7.2
            && !packedEntropyReported)
        {
            add(25, "High-entropy code section (packed or encrypted)");
            packedEntropyReported = true;
        }
    }

    // overlapping raw ranges
    {
        std::vector<std::pair<std::uint32_t, std::uint32_t>> ranges;

        for (const PeSectionInfo& s : report.sections)
            if (s.rawSize > 0)
                ranges.emplace_back(s.rawOffset, s.rawOffset + s.rawSize);

        std::sort(ranges.begin(), ranges.end());

        for (std::size_t i = 1; i < ranges.size(); ++i)
        {
            if (ranges[i].first < ranges[i - 1].second)
            {
                add(10, "Overlapping section data");
                break;
            }
        }
    }

    // ---- imports --------------------------------------------------------
    std::unordered_set<std::string> apis;

    {
        std::uint32_t minVa = 0xFFFFFFFFu;
        for (const PeSectionInfo& s : report.sections)
            minVa = std::min(minVa, s.virtualAddress);

        const Rva mapper{ &report.sections, minVa, size };

        std::size_t descOffset = 0;

        if (dirs[1].rva != 0 && mapper.toOffset(dirs[1].rva, descOffset))
        {
            for (std::size_t k = 0; k < kMaxImportDlls; ++k)
            {
                std::uint32_t oft = 0, nameRva = 0, ft = 0;
                const std::size_t at = descOffset + 20 * k;

                if (!rd(data, size, at, oft)
                    || !rd(data, size, at + 12, nameRva)
                    || !rd(data, size, at + 16, ft))
                {
                    break;
                }

                if (oft == 0 && nameRva == 0 && ft == 0)
                    break;

                std::size_t nameOffset = 0;
                std::string dllName;

                if (mapper.toOffset(nameRva, nameOffset)
                    && readCString(data, size, nameOffset, 64, dllName)
                    && lowerCopy(dllName) == "mscoree.dll")
                {
                    report.isDotNet = true;
                }

                const std::uint32_t thunkRva = oft != 0 ? oft : ft;
                std::size_t thunkOffset = 0;

                if (!mapper.toOffset(thunkRva, thunkOffset))
                    continue;

                const std::size_t step = report.is64 ? 8 : 4;

                for (std::size_t j = 0; j < kMaxThunksPerDll; ++j)
                {
                    std::uint64_t value = 0;

                    if (report.is64)
                    {
                        if (!rd(data, size, thunkOffset + j * step, value))
                            break;
                    }
                    else
                    {
                        std::uint32_t v32 = 0;

                        if (!rd(data, size, thunkOffset + j * step, v32))
                            break;

                        value = v32;
                    }

                    if (value == 0)
                        break;

                    ++report.importFunctionCount;

                    const std::uint64_t ordinalFlag =
                        report.is64 ? (1ull << 63) : (1ull << 31);

                    if (value & ordinalFlag)
                        continue;

                    std::size_t hintOffset = 0;
                    std::string fn;

                    if (mapper.toOffset(static_cast<std::uint32_t>(value & 0x7FFFFFFFu), hintOffset)
                        && readCString(data, size, hintOffset + 2, 128, fn))
                    {
                        apis.insert(lowerCopy(fn));
                    }
                }
            }
        }
    }

    const auto has = [&apis](const char* name) { return apis.count(name) != 0; };
    const auto hasAny = [&has](std::initializer_list<const char*> names) {
        for (const char* n : names)
            if (has(n))
                return true;
        return false;
    };

    if (!report.isDotNet && !report.isDll && size >= 20000
        && report.importFunctionCount <= 4)
    {
        add(25, "Almost no imports (typical for packed programs)");
    }

    if (hasAny({ "virtualallocex", "ntallocatevirtualmemory", "zwallocatevirtualmemory" })
        && hasAny({ "writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory" })
        && hasAny({ "createremotethread", "createremotethreadex", "ntcreatethreadex",
                    "queueuserapc", "rtlcreateuserthread", "setthreadcontext" }))
    {
        add(35, "Process-injection API combination");
    }

    if (hasAny({ "ntunmapviewofsection", "zwunmapviewofsection" })
        && has("writeprocessmemory")
        && hasAny({ "setthreadcontext", "resumethread" }))
    {
        add(35, "Process-hollowing API combination");
    }

    if (hasAny({ "setwindowshookexa", "setwindowshookexw" })
        && hasAny({ "getasynckeystate", "getkeyboardstate", "getkeystate" }))
    {
        add(25, "Keylogging API combination");
    }

    if (hasAny({ "urldownloadtofilea", "urldownloadtofilew" })
        && hasAny({ "shellexecutea", "shellexecutew", "shellexecuteexa", "shellexecuteexw",
                    "winexec", "createprocessa", "createprocessw" }))
    {
        add(25, "Downloads a file and executes it");
    }

    {
        int antiDebug = 0;
        for (const char* n : { "isdebuggerpresent", "checkremotedebuggerpresent",
                               "ntqueryinformationprocess", "outputdebugstringa" })
            antiDebug += has(n) ? 1 : 0;

        if (antiDebug >= 3)
            add(10, "Several anti-debugging APIs");
    }

    // ---- strings --------------------------------------------------------
    int scoreSoFar = 0;
    for (const Finding& f : findings)
        scoreSoFar += f.weight;

    if (size <= kStringScanFullLimit || scoreSoFar >= 15)
    {
        const std::size_t span = std::min(size, kStringScanMaxBytes);
        std::vector<std::uint8_t> lowered(data, data + span);

        for (std::uint8_t& b : lowered)
            if (b >= 'A' && b <= 'Z')
                b = static_cast<std::uint8_t>(b - 'A' + 'a');

        struct Pattern { const char* text; int weight; const char* reason; };

        static const Pattern kPatterns[] = {
            { "your files have been encrypted", 60, "Ransom-note text" },
            { "decrypt your files",             60, "Ransom-note text" },
            { "sekurlsa::logonpasswords",       60, "Credential-dumping command (mimikatz)" },
            { "mimikatz",                       40, "References mimikatz" },
            { "meterpreter",                    50, "References Meterpreter payload" },
            { "delete shadows",                 35, "Deletes volume shadow copies" },
            { "shadowcopy delete",              35, "Deletes volume shadow copies" },
            { "recoveryenabled no",             30, "Disables Windows recovery" },
            { "-encodedcommand",                20, "Runs an encoded PowerShell command" },
            { ".onion",                         15, "Contains a Tor address" },
            { "currentversion\\run",            10, "Writes to the autorun registry key" },
        };

        std::unordered_set<std::string> seenReasons;

        for (const Pattern& p : kPatterns)
        {
            const std::string ascii = p.text;

            if (contains(lowered, ascii) || contains(lowered, toUtf16le(ascii)))
            {
                if (seenReasons.insert(p.reason).second)
                    add(p.weight, p.reason);
            }
        }
    }

    // ---- overlay --------------------------------------------------------
    {
        std::size_t end = 0;

        for (const PeSectionInfo& s : report.sections)
            if (s.rawSize > 0)
                end = std::max<std::size_t>(end, static_cast<std::size_t>(s.rawOffset) + s.rawSize);

        std::size_t overlay = (end < size) ? size - end : 0;

        if (report.hasEmbeddedSignature)
            overlay = overlay > dirs[4].size ? overlay - dirs[4].size : 0;

        if (overlay > 100 * 1024 && overlay * 2 > size)
        {
            if (shannonEntropy(data + end, std::min(overlay, kMaxEntropyBytes)) > 7.3)
                add(15, "Large encrypted or compressed overlay");
        }
    }

    // ---- result ---------------------------------------------------------
    std::stable_sort(findings.begin(), findings.end(),
        [](const Finding& a, const Finding& b) { return a.weight > b.weight; });

    for (const Finding& f : findings)
        report.score += f.weight;

    for (std::size_t i = 0; i < findings.size() && i < 6; ++i)
        report.reasons.push_back(findings[i].text);

    return report;
}
}
