#include "realtime_protection.h"

#include <QCoreApplication>
#include <QDir>
#include <QMetaObject>
#include <QString>

namespace
{
    // The app's own data folder, the install folder and %TEMP% are never
    // scanned: writing the database, the cache or an update must not feed
    // the queue with files the app itself just created.
    std::vector<std::filesystem::path> ExcludedDirectories(
        const QString& databasePath)
    {
        std::vector<std::filesystem::path> excluded;

        const QStringList candidates = {
            QDir::tempPath(),
            QDir(databasePath).absolutePath(),
            QCoreApplication::applicationDirPath()
        };

        for (const QString& path : candidates)
        {
            if (!path.isEmpty())
                excluded.emplace_back(path.toStdWString());
        }

        return excluded;
    }
}

RealtimeProtection::RealtimeProtection(QObject* parent)
    : QObject(parent),
    m_queue(this)
{
    connect(
        &m_queue,
        &RealtimeQueue::statusChanged,
        this,
        &RealtimeProtection::statusChanged
    );

    connect(
        &m_queue,
        &RealtimeQueue::fileScanned,
        this,
        &RealtimeProtection::fileScanned
    );

    connect(
        &m_queue,
        &RealtimeQueue::threatDetected,
        this,
        &RealtimeProtection::threatDetected
    );
}

RealtimeProtection::~RealtimeProtection()
{
    stop();
}

bool RealtimeProtection::active() const
{
    return m_active.load();
}

bool RealtimeProtection::start(
    const QStringList& directories,
    const QString& databasePath,
    const QString& cachePath)
{
    stop();

    std::vector<std::filesystem::path> roots;

    for (const QString& directory : directories)
    {
        const QString absolute = QDir(directory).absolutePath();

        if (QDir(absolute).exists())
            roots.emplace_back(absolute.toStdWString());
    }

    if (roots.empty())
    {
        emit statusChanged(
            QStringLiteral("Real-Time Protection: no valid directories")
        );

        return false;
    }

    if (!m_queue.start(
        std::filesystem::path(databasePath.toStdWString()),
        std::filesystem::path(cachePath.toStdWString()),
        ExcludedDirectories(databasePath)))
    {
        return false;
    }

    const bool watcherStarted = m_watcher.start(
        roots,
        [this](const std::filesystem::path& file)
        {
            m_queue.enqueue(file);
        }
    );

    if (!watcherStarted)
    {
        m_queue.stop();

        emit statusChanged(
            QStringLiteral("Real-Time Protection: watcher failed to start")
        );

        return false;
    }

    m_active = true;
    emit activeChanged();

    emit statusChanged(
        QStringLiteral("Real-Time Protection: active")
    );

    return true;
}

void RealtimeProtection::stop()
{
    const bool wasActive = m_active.exchange(false);

    m_watcher.stop();
    m_queue.stop();

    if (wasActive)
        emit activeChanged();
}