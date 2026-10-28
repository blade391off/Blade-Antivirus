#include "scan_cache.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

namespace blade
{
namespace
{
    constexpr std::uint32_t kMagic = 0x43444C42u; // "BLDC"
    constexpr std::uint32_t kFormat = 1;
    constexpr std::size_t kHeaderBytes = 24;
    constexpr std::size_t kEntryBytes = 8 + 8 + 8 + 32;

    template <typename T>
    void put(std::vector<char>& out, T value)
    {
        const char* p = reinterpret_cast<const char*>(&value);
        out.insert(out.end(), p, p + sizeof(T));
    }

    template <typename T>
    T get(const char* p)
    {
        T value;
        std::memcpy(&value, p, sizeof(T));
        return value;
    }
}

std::uint64_t ScanCache::keyOf(const std::filesystem::path& path)
{
    // FNV-1a over the native path. ASCII letters are folded to lower case
    // because Windows paths are case-insensitive.
    std::uint64_t hash = 1469598103934665603ull;

    for (auto ch : path.native())
    {
        std::uint32_t c = static_cast<std::uint32_t>(ch);

        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';

        for (int shift = 0; shift < 32; shift += 8)
        {
            hash ^= (c >> shift) & 0xFFu;
            hash *= 1099511628211ull;
        }
    }

    return hash;
}

void ScanCache::clear()
{
    map_.clear();
    dirty_ = false;
}

std::size_t ScanCache::load(const std::filesystem::path& file,
                            std::uint32_t engineVersion)
{
    clear();

    std::ifstream in(file, std::ios::binary);

    if (!in)
        return 0;

    char header[kHeaderBytes];

    if (!in.read(header, sizeof(header)))
        return 0;

    if (get<std::uint32_t>(header) != kMagic
        || get<std::uint32_t>(header + 4) != kFormat
        || get<std::uint32_t>(header + 8) != engineVersion)
    {
        return 0; // other engine version: heuristics changed, rescan everything
    }

    const std::uint64_t count = get<std::uint64_t>(header + 16);

    if (count > kMaxEntries)
        return 0;

    std::vector<char> body(static_cast<std::size_t>(count) * kEntryBytes);

    if (!body.empty() && !in.read(body.data(), static_cast<std::streamsize>(body.size())))
        return 0;

    // The file must end exactly here, otherwise treat it as damaged.
    if (in.peek() != std::ifstream::traits_type::eof())
        return 0;

    map_.reserve(static_cast<std::size_t>(count));

    for (std::uint64_t i = 0; i < count; ++i)
    {
        const char* p = body.data() + i * kEntryBytes;
        Entry e;
        const std::uint64_t key = get<std::uint64_t>(p);
        e.size = get<std::uint64_t>(p + 8);
        e.mtime = get<std::uint64_t>(p + 16);
        std::memcpy(e.sha256.data(), p + 24, 32);
        map_[key] = e;
    }

    dirty_ = false;
    return map_.size();
}

bool ScanCache::find(const std::filesystem::path& path, std::uint64_t size,
                     std::uint64_t mtime, Digest& sha256) const
{
    const auto it = map_.find(keyOf(path));

    if (it == map_.end() || it->second.size != size || it->second.mtime != mtime)
        return false;

    it->second.touched = true;
    sha256 = it->second.sha256;
    return true;
}

void ScanCache::add(const std::filesystem::path& path, std::uint64_t size,
                    std::uint64_t mtime, const Digest& sha256)
{
    const std::uint64_t key = keyOf(path);
    const auto it = map_.find(key);

    if (it == map_.end() && map_.size() >= kMaxEntries)
        return; // full: stale entries are pruned on save

    Entry e;
    e.size = size;
    e.mtime = mtime;
    e.sha256 = sha256;
    e.touched = true;
    map_[key] = e;
    dirty_ = true;
}

bool ScanCache::save(const std::filesystem::path& file, std::uint32_t engineVersion)
{
    // Nearly full: forget files that were not seen in this session
    // (deleted or moved files would otherwise live forever).
    if (map_.size() > kMaxEntries / 10 * 9)
    {
        for (auto it = map_.begin(); it != map_.end();)
        {
            if (!it->second.touched)
                it = map_.erase(it);
            else
                ++it;
        }
    }

    std::vector<char> out;
    out.reserve(kHeaderBytes + map_.size() * kEntryBytes);

    put<std::uint32_t>(out, kMagic);
    put<std::uint32_t>(out, kFormat);
    put<std::uint32_t>(out, engineVersion);
    put<std::uint32_t>(out, 0);
    put<std::uint64_t>(out, static_cast<std::uint64_t>(map_.size()));

    for (const auto& kv : map_)
    {
        put<std::uint64_t>(out, kv.first);
        put<std::uint64_t>(out, kv.second.size);
        put<std::uint64_t>(out, kv.second.mtime);
        out.insert(out.end(), kv.second.sha256.begin(), kv.second.sha256.end());
    }

    std::error_code ec;
    const std::filesystem::path parent = file.parent_path();

    if (!parent.empty())
        std::filesystem::create_directories(parent, ec);

    std::filesystem::path temp = file;
    temp += ".tmp";

    {
        std::ofstream o(temp, std::ios::binary | std::ios::trunc);

        if (!o)
            return false;

        o.write(out.data(), static_cast<std::streamsize>(out.size()));
        o.flush();

        if (!o)
        {
            o.close();
            std::filesystem::remove(temp, ec);
            return false;
        }
    }

    std::filesystem::rename(temp, file, ec);

    if (ec)
    {
        std::filesystem::remove(temp, ec);
        return false;
    }

    dirty_ = false;
    return true;
}
}
