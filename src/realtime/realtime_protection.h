#pragma once

#include <QObject>
#include <QStringList>

#include <atomic>
#include <filesystem>
#include <vector>

#include "file_watcher.h"
#include "realtime_queue.h"

class RealtimeProtection final : public QObject
{
    Q_OBJECT

        Q_PROPERTY(bool active READ active NOTIFY activeChanged)

public:
    explicit RealtimeProtection(QObject* parent = nullptr);
    ~RealtimeProtection() override;

    RealtimeProtection(const RealtimeProtection&) = delete;
    RealtimeProtection& operator=(const RealtimeProtection&) = delete;

    bool active() const;

    Q_INVOKABLE bool start(
        const QStringList& directories,
        const QString& databasePath,
        const QString& cachePath
    );

    Q_INVOKABLE void stop();

signals:
    void activeChanged();
    void statusChanged(const QString& status);

    void fileScanned(
        const QString& path,
        const QString& verdict,
        const QString& sha256,
        const QString& details
    );

    void threatDetected(
        const QString& path,
        const QString& verdict,
        const QString& details
    );

private:
    std::atomic_bool m_active{ false };

    FileWatcher m_watcher;
    RealtimeQueue m_queue;
};