
#pragma once

#include <QObject>
#include <QString>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

class BehaviorMonitor final : public QObject
{
    Q_OBJECT

        Q_PROPERTY(bool active READ active NOTIFY activeChanged)

public:
    explicit BehaviorMonitor(QObject* parent = nullptr);
    ~BehaviorMonitor() override;

    BehaviorMonitor(const BehaviorMonitor&) = delete;
    BehaviorMonitor& operator=(const BehaviorMonitor&) = delete;

    bool active() const;

    Q_INVOKABLE bool start();
    Q_INVOKABLE void stop();

signals:
    void activeChanged();
    void statusChanged(const QString& status);

    void processObserved(
        quint32 pid,
        const QString& path,
        int riskScore,
        const QString& verdict,
        const QString& details
    );

private:
    void worker();

    std::atomic_bool m_active{ false };

    std::thread m_worker;
    std::mutex m_mutex;
    std::condition_variable m_condition;
};
