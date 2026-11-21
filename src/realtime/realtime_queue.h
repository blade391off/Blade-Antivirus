#pragma once

#include <QObject>
#include <QString>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

class RealtimeQueue final : public QObject
{
    Q_OBJECT

public:
    explicit RealtimeQueue(QObject* parent = nullptr);
    ~RealtimeQueue() override;

    RealtimeQueue(const RealtimeQueue&) = delete;
    RealtimeQueue& operator=(const RealtimeQueue&) = delete;

    // `excludedDirectories` are never queued: the app's own data folder,
    // the temp folder and the install folder would otherwise feed the queue
    // with files the app itself just wrote.
    bool start(
        const std::filesystem::path& databasePath,
        const std::filesystem::path& cachePath,
        const std::vector<std::filesystem::path>& excludedDirectories = {}
    );

    void stop();

    void enqueue(const std::filesystem::path& file);

    bool running() const;

signals:
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
    struct Item
    {
        std::filesystem::path path;
        std::chrono::steady_clock::time_point readyAt;
        int priority = 1; // 0 = runs code, 1 = archives and documents
    };

    void worker(
        std::filesystem::path databasePath,
        std::filesystem::path cachePath
    );

    std::atomic_bool m_running{ false };

    std::thread m_thread;

    std::mutex m_mutex;
    std::condition_variable m_condition;

    std::vector<Item> m_queue;
    std::unordered_set<std::wstring> m_pending;
    std::vector<std::filesystem::path> m_excludedDirectories;

    std::size_t m_dropped = 0;
    std::chrono::steady_clock::time_point m_lastOverloadNotice{};
};
