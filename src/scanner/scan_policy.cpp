#include "scan_policy.h"

#include <string>
#include <unordered_set>

namespace blade
{
namespace
{
    std::filesystem::path::string_type fold(const std::filesystem::path& p)
    {
        auto s = p.native();

        for (auto& ch : s)
        {
            if (ch >= 'A' && ch <= 'Z')
                ch = static_cast<typename decltype(s)::value_type>(ch - 'A' + 'a');
            else if (ch == '/')
                ch = '\\';
        }

        return s;
    }
}

bool hasScannableExtension(const std::filesystem::path& path)
{
    static const std::unordered_set<std::string> kExtensions = {
        // native code
        "exe", "dll", "sys", "scr", "com", "pif", "cpl", "ocx", "drv", "efi",
        // installers
        "msi", "msp", "mst", "appx", "msix",
        // scripts
        "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "hta", "jar", "jnlp", "reg", "inf",
        // shortcuts / help / web
        "lnk", "url", "chm",
        // documents that can carry macros
        "doc", "dot", "xls", "xlt", "ppt", "rtf",
        "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "ppam",
        // containers
        "zip", "rar", "7z", "iso", "img", "cab"
    };

    const auto ext = fold(path.extension());

    if (ext.size() < 2) // "" or "."
        return false;

    std::string narrow;

    for (std::size_t i = 1; i < ext.size(); ++i)
    {
        const auto ch = ext[i];

        if (ch > 0x7E || ch < 0x20)
            return false;

        narrow.push_back(static_cast<char>(ch));
    }

    return kExtensions.count(narrow) != 0;
}

bool isInsideDirectory(const std::filesystem::path& path,
                       const std::filesystem::path& dir)
{
    auto p = fold(path);
    auto d = fold(dir);

    while (!d.empty() && d.back() == '\\')
        d.pop_back();

    if (d.empty() || p.size() < d.size())
        return false;

    if (p.compare(0, d.size(), d) != 0)
        return false;

    return p.size() == d.size() || p[d.size()] == '\\';
}
}
