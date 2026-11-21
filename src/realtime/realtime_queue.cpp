#include "realtime_queue.h"

#include "../scanner/scan_policy.h"
#include "../scanner/scanner.h"

#include <QMetaObject>

#include <algorithm>
#include <system_error>
#include <utility>

namespace
{
    // Bounded queue: unpacking a large archive generates thousands of
    // notifications in seconds. Dropping excess work is better than growing
    // without limit and scanning stale files minutes later.
    constexpr std::size_t kMaxQueuedFiles = 256;

    // A file is scanned only after the writes have settled, so a partially
    // written executable is not hashed while it is still growing.
    constexpr auto kSettleDelay = std::chrono::milliseconds(750);

    constexpr auto kOverloadNoticeInterval = std::chrono::seconds(30);

    // Tighter than a manual scan: background work must not block the queue.
    const ScanLimits kRealtimeLimits{
        blade::kRealtimeMaxFileSize,
        32ull * 1024 * 1024,
        5
    };

    QString toQString(const std::string& value)
    {
        return QString::fromLatin1(
            value.data(),
            static_cast<qsizetype>(value.size()));
    }
}

RealtimeQueue::RealtimeQueue(QObject* parent)
    : QObject(parent)
{
}

RealtimeQueue::~RealtimeQueue()
{
    stop();
}

bool RealtimeQueue::start(
    const std::filesystem::path& databasePath,
    const std::filesystem::path& cachePath,
    const std::vector<std::filesystem::path>& excludedDirectories)
{
    stop();

    {
        std::lock_guard lock(m_mutex);

        m_queue.clear();
        m_pending.clear();
        m_excludedDirectories = excludedDirectories;
        m_dropped = 0;
        m_lastOverloadNotice = {};
    }

    m_running = true;

    m_thread = std::thread(
        [this, databasePath, cachePath]()
        {
            worker(databasePath, cachePath);
        }
    );

    return true;
}

void RealtimeQueue::stop()
{
    m_running = false;
    m_condition.notify_all();

    if (m_thread.joinable())
        m_thread.join();

    {
        std::lock_guard lock(m_mutex);

        m_queue.clear();
        m_pending.clear();
    }
}

bool RealtimeQueue::running() const
{
    return m_running.load();
}

void RealtimeQueue::enqueue(const std::filesystem::path& file)
{
    if (!m_running)
        return;

    const std::filesystem::path normalized = file.lexically_normal();

    std::error_code error;

    if (!std::filesystem::is_regular_file(normalized, error) || error)
        return;

    // Photos, text, video and everything else the scanner cannot act on.
    if (!blade::hasScannableExtension(normalized))
        return;

    // The app's own database, cache and install folder.
    if (blade::isInsideAnyDirectory(normalized, m_excludedDirectories))
        return;

    const std::uintmax_t size =
        std::filesystem::file_size(normalized, error);

    if (error || size == 0 || size > blade::kRealtimeMaxFileSize)
        return;

    const auto now = std::chrono::steady_clock::now();
    const std::wstring key = normalized.wstring();

    bool overloaded = false;
    std::size_t droppedTotal = 0;

    {
        std::lock_guard lock(m_mutex);

        if (!m_running)
            return;

        // Already scheduled (an editor or archiver rewriting the same file):
        // postpone instead of queueing it twice.
        if (!m_pending.insert(key).second)
        {
            for (Item& item : m_queue)
            {
                if (item.path.native() == normalized.native())
                {
                    item.readyAt = now + kSettleDelay;
                    break;
                }
            }

            return;
        }

        if (m_queue.size() >= kMaxQueuedFiles)
        {
            m_pending.erase(key);
            ++m_dropped;
            droppedTotal = m_dropped;

            overloaded = now - m_lastOverloadNotice > kOverloadNoticeInterval;

            if (overloaded)
                m_lastOverloadNotice = now;
        }
        else
        {
            m_queue.push_back(
                Item{
                    normalized,
                    now + kSettleDelay,
                    blade::isCodeExtension(normalized) ? 0 : 1
                }
            );
        }
    }

    if (overloaded)
    {
        // Emitted from a watcher thread: hop to the GUI thread.
        QMetaObject::invokeMethod(
            this,
            [this, droppedTotal]()
            {
                emit statusChanged(
                    QStringLiteral(
                        "Real-Time Protection: queue overloaded, "
                        "%1 file(s) skipped")
                    .arg(static_cast<qulonglong>(droppedTotal)));
            },
            Qt::QueuedConnection);

        return;
    }

    m_condition.notify_one();
}

void RealtimeQueue::worker(
    std::filesystem::path databasePath,
    std::filesystem::path cachePath)
{
    Scanner scanner;

    if (!scanner.initialize(databasePath, cachePath))
    {
        emit statusChanged(
            QStringLiteral("Real-Time Protection: scanner initialization failed")
        );

        m_running = false;
        m_condition.notify_all();
        return;
    }

    emit statusChanged(
        QStringLiteral("Real-Time Protection: monitoring files")
    );

    while (true)
    {
        std::filesystem::path file;

        {
            std::unique_lock lock(m_mutex);

            for (;;)
            {
                if (!m_running)
                    break;

                const auto now = std::chrono::steady_clock::now();

                // Ready files first; among them, code before documents.
                auto best = m_queue.end();

                for (auto it = m_queue.begin(); it != m_queue.end(); ++it)
                {
                    if (it->readyAt > now)
                        continue;

                    if (best == m_queue.end() || it->priority < best->priority)
                        best = it;
                }

                if (best != m_queue.end())
                {
                    file = std::move(best->path);
                    m_queue.erase(best);
                    break;
                }

                if (m_queue.empty())
                {
                    m_condition.wait(lock);
                    continue;
                }

                // Nothing is ready yet: sleep until the earliest settle time.
                auto earliest = now + std::chrono::hours(1);

                for (const Item& item : m_queue)
                    earliest = std::min(earliest, item.readyAt);

                m_condition.wait_until(lock, earliest);
            }
        }

        if (file.empty())
            break;

        const ScanResult result = scanner.scan(file, kRealtimeLimits);

        const QString path = QString::fromStdWString(result.file);
        const QString verdict = toQString(result.verdict);
        const QString details = QString::fromUtf8(
            result.details.data(),
            static_cast<qsizetype>(result.details.size()));

        emit fileScanned(
            path,
            verdict,
            toQString(result.sha256),
            details);

        if (result.verdict == "MALICIOUS"
            || result.verdict == "SUSPICIOUS")
        {
            emit threatDetected(path, verdict, details);
        }

        {
            std::lock_guard lock(m_mutex);
            m_pending.erase(file.wstring());
        }
    }

    scanner.saveCache();

    emit statusChanged(
        QStringLiteral("Real-Time Protection: stopped")
    );
}
