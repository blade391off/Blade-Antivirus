
#pragma once

#include <QObject>
#include <QString>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

class ScanController final : public QObject
{
    Q_OBJECT

public:
    explicit ScanController(QObject* parent = nullptr);
    ~ScanController() override;

    Q_INVOKABLE bool startScan(
        const QString& targetPath,
        bool recursive = true);

    Q_INVOKABLE void pauseScan();
    Q_INVOKABLE void resumeScan();
    Q_INVOKABLE void cancelScan();

signals:
    void statusChanged(const QString& status);

    void progressChanged(
        int percentage,
        int checkedFiles,
        int totalFiles,
        const QString& currentFile);

    void fileChecked(
        const QString& displayName,
        const QString& verdict,
        const QString& details);

    void scanFinished(
        int checkedFiles,
        int threatsFound,
        bool cancelled);

private:
    void runScan(QString targetPath, bool recursive);
    void waitIfPaused();
    void publishStatus(const QString& status);

    std::thread worker_;
    std::atomic<bool> running_{ false };
    std::atomic<bool> cancelled_{ false };
    std::atomic<bool> paused_{ false };

    std::mutex pauseMutex_;
    std::condition_variable pauseCondition_;
};
