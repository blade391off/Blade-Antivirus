#include "pending_queue.h"

#include <algorithm>

namespace blade
{
PendingQueue::PendingQueue(Millis settle, std::size_t maxEntries, int maxRetries)
    : settle_(settle)
    , maxEntries_(maxEntries)
    , maxRetries_(maxRetries)
{
}

PendingQueue::Key PendingQueue::keyOf(const std::filesystem::path& path)
{
    Key key = path.native();

    for (auto& ch : key)
    {
        if (ch >= 'A' && ch <= 'Z')
            ch = static_cast<typename Key::value_type>(ch - 'A' + 'a');
        else if (ch == '/')
            ch = '\\';
    }

    return key;
}

void PendingQueue::touch(const std::filesystem::path& path, Clock::time_point now)
{
    const Key key = keyOf(path);
    const auto it = entries_.find(key);

    if (it != entries_.end())
    {
        it->second.readyAt = now + settle_; // still being written: wait again
        return;
    }

    if (entries_.size() >= maxEntries_)
    {
        ++dropped_;
        return;
    }

    entries_[key] = Entry{ path, now + settle_ };
}

std::vector<std::filesystem::path> PendingQueue::takeReady(Clock::time_point now,
                                                           std::size_t limit)
{
    std::vector<const Entry*> ready;

    for (const auto& kv : entries_)
        if (kv.second.readyAt <= now)
            ready.push_back(&kv.second);

    // Oldest first, so nothing starves.
    std::sort(ready.begin(), ready.end(),
        [](const Entry* a, const Entry* b) { return a->readyAt < b->readyAt; });

    if (ready.size() > limit)
        ready.resize(limit);

    std::vector<std::filesystem::path> out;
    out.reserve(ready.size());

    for (const Entry* e : ready)
        out.push_back(e->path);

    for (const auto& p : out)
        entries_.erase(keyOf(p));

    return out;
}

void PendingQueue::done(const std::filesystem::path& path)
{
    retries_.erase(keyOf(path));
}

bool PendingQueue::retryLater(const std::filesystem::path& path, Clock::time_point now)
{
    const Key key = keyOf(path);
    const int attempt = ++retries_[key];

    if (attempt > maxRetries_)
    {
        retries_.erase(key);
        return false;
    }

    // settle, 2x, 4x, 8x, 16x (capped at 30 s)
    auto delay = settle_ * (1 << std::min(attempt - 1, 4));
    delay = std::min<Millis>(delay, Millis(30000));

    if (entries_.find(key) == entries_.end() && entries_.size() < maxEntries_)
        entries_[key] = Entry{ path, now + delay };
    else if (entries_.find(key) != entries_.end())
        entries_[key].readyAt = std::max(entries_[key].readyAt, now + delay);

    return true;
}

std::optional<PendingQueue::Clock::time_point> PendingQueue::nextReadyTime() const
{
    std::optional<Clock::time_point> best;

    for (const auto& kv : entries_)
        if (!best || kv.second.readyAt < *best)
            best = kv.second.readyAt;

    return best;
}
}
