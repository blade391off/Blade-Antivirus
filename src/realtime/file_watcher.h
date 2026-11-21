#pragma once

#include <atomic>
#include <filesystem>
#include <functional>
#include <thread>
#include <vector>

class FileWatcher final
{
public:
    using Callback = std::function<void(const std::filesystem::path&)>;

    FileWatcher() = default;
    ~FileWatcher();

    FileWatcher(const FileWatcher&) = delete;
    FileWatcher& operator=(const FileWatcher&) = delete;

    bool start(
        const std::vector<std::filesystem::path>& roots,
        Callback callback
    );

    void stop();

    bool running() const;

private:
    void watchDirectory(
        std::filesystem::path directory,
        Callback callback
    );

    std::atomic_bool m_running{ false };
    std::vector<std::thread> m_threads;
};