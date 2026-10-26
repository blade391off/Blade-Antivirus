#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QUrl>

#include <atomic>
#include <thread>

class AntivirusController : public QObject
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
    void statusChanged(const QString& message);
    void scanningChanged();
    void scanProgress(const QString& message);
    void fileScanned(
        const QString& path,
        const QString& verdict,
        const QString& sha256);
    void scanFinished(int scanned, int detected, int errors);

private:
    void startScan(const QStringList& folders);

    std::atomic_bool m_scanning{ false };
    std::atomic_bool m_stopRequested{ false };
    std::atomic_bool m_updating{ false };

    std::thread m_worker;
    std::thread m_updateWorker;
};
