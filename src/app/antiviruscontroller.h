#pragma once

#include <QObject>
#include <QUrl>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <atomic>
#include <thread>

class AntivirusController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool scanning READ scanning NOTIFY scanningChanged)

public:
    explicit AntivirusController(QObject* parent = nullptr);
    ~AntivirusController() override;

    bool scanning() const;

    Q_INVOKABLE void startQuickScan();
    Q_INVOKABLE void startFullScan();
    Q_INVOKABLE void startCustomScan(const QUrl& folderUrl);
    Q_INVOKABLE void stopScan();
    Q_INVOKABLE void checkUpdates();

signals:
    void scanningChanged();
    void statusChanged(const QString& message);
    void scanProgress(const QString& message);
    // Only MALICIOUS and SUSPICIOUS files are reported here.
    // `details` explains the verdict (heuristic reasons / blocklist match).
    void fileScanned(
        const QString& path,
        const QString& verdict,
        const QString& sha256,
        const QString& details
    );
    void scanFinished(
        int scanned,
        int detected,
        int errors
    );
    // Live numbers for the scan window (about 4 times per second).
    void scanStats(
        int scanned,
        int detected,
        int suspicious,
        int errors,
        int skipped,
        qint64 elapsedMs,
        const QString& currentFile
    );
    // Final report. `failure` is empty unless the scan could not run.
    void scanSummary(
        int scanned,
        int detected,
        int suspicious,
        int errors,
        int skipped,
        qint64 elapsedMs,
        bool stopped,
        const QString& failure
    );
    // Emitted when an update run ends (manual or automatic).
    void updateFinished(bool ok);

private:
    void startScan(const QStringList& folders);
    void startUpdate(bool manual);

    std::atomic_bool m_scanning{ false };
    std::atomic_bool m_stopRequested{ false };
    std::atomic_bool m_updating{ false };
    std::thread m_worker;
    std::thread m_updateWorker;

    QTimer m_updateTimer;       // automatic updates every 1 h 59 min
    int m_updateFailures = 0;   // GUI thread only; drives the retry back-off
};
