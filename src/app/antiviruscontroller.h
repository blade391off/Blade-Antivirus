#pragma once

#include <QObject>
#include <QUrl>
#include <QString>
#include <QStringList>
#include <QTimer>

#include <atomic>
#include <thread>

#include "realtime/realtime_protection.h"

class AntivirusController final : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool scanning READ scanning NOTIFY scanningChanged)
    Q_PROPERTY(bool databaseAvailable READ databaseAvailable NOTIFY databaseAvailableChanged)
    Q_PROPERTY(QStringList exclusions READ exclusions NOTIFY exclusionsChanged)
    Q_PROPERTY(bool scheduledScanEnabled READ scheduledScanEnabled NOTIFY scheduledScanEnabledChanged)
    Q_PROPERTY(int scheduledScanIntervalMinutes READ scheduledScanIntervalMinutes NOTIFY scheduledScanIntervalMinutesChanged)
    Q_PROPERTY(RealtimeProtection* realtimeProtection READ realtimeProtection CONSTANT)

public:
    explicit AntivirusController(QObject* parent = nullptr);
    ~AntivirusController() override;

    bool scanning() const;
    bool databaseAvailable() const;

    RealtimeProtection* realtimeProtection() { return &m_realtimeProtection; }

    QStringList exclusions() const;
    bool scheduledScanEnabled() const;
    int scheduledScanIntervalMinutes() const;

    Q_INVOKABLE void startQuickScan();
    Q_INVOKABLE void startFullScan();
    Q_INVOKABLE void startCustomScan(const QUrl& folderUrl);
    Q_INVOKABLE void startPathsScan(const QStringList& paths);
    Q_INVOKABLE void scanRunningProcesses();
    Q_INVOKABLE void setRealtimeProtectionEnabled(bool enabled);
    Q_INVOKABLE void stopScan();

    Q_INVOKABLE void checkUpdates();

    // Exclusions management.
    Q_INVOKABLE void addExclusion(const QString& path);
    Q_INVOKABLE void removeExclusion(const QString& path);
    Q_INVOKABLE void clearExclusions();

    // Quarantine management.
    Q_INVOKABLE bool quarantineFile(const QString& path);
    Q_INVOKABLE bool restoreQuarantined(const QString& id);
    Q_INVOKABLE bool deleteQuarantined(const QString& id);
    Q_INVOKABLE QStringList quarantinedFiles() const;

    // Scheduled scanning.
    Q_INVOKABLE void setScheduledScanEnabled(bool enabled);
    Q_INVOKABLE void setScheduledScanIntervalMinutes(int minutes);

    // Export last scan results.
    Q_INVOKABLE bool exportLastScanReport(const QString& filePath) const;

    // Scan history.
    Q_INVOKABLE QStringList recentScanHistory() const;

signals:
    void scanningChanged();
    void databaseAvailableChanged();
    void exclusionsChanged();
    void scheduledScanEnabledChanged();
    void scheduledScanIntervalMinutesChanged();
    void threatDetected(const QString& path, const QString& verdict, const QString& details);
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

    // Re-reads the database state and reports it in the UI. Runs on the GUI
    // thread only.
    void publishDatabaseStatus();

    std::atomic_bool m_scanning{ false };
    std::atomic_bool m_stopRequested{ false };
    std::atomic_bool m_updating{ false };
    std::thread m_worker;
    std::thread m_updateWorker;

    QTimer m_updateTimer;       // automatic updates every 1 h 59 min
    QTimer m_scheduledScanTimer;
    RealtimeProtection m_realtimeProtection;
    int m_updateFailures = 0;   // GUI thread only; drives the retry back-off
    bool m_databaseAvailable = false; // GUI thread only

    QStringList m_exclusions;
    bool m_scheduledScanEnabled = false;
    int m_scheduledScanIntervalMinutes = 60;

    // Last scan results for export.
    struct ScanEntry { QString path; QString verdict; QString sha256; QString details; };
    std::vector<ScanEntry> m_lastScanResults;

    bool isExcluded(const QString& path) const;
    void loadSettings();
    void saveSettings();
    void appendScanHistory(int scanned, int detected, int suspicious, int errors, int skipped, qint64 elapsedMs);
    QString quarantineRoot() const;
};
