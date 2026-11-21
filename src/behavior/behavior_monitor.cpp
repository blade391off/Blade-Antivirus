
#include "behavior_monitor.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <unordered_map>
#include <vector>

namespace
{
    using ProcessMap = std::unordered_map<DWORD, std::wstring>;

    bool getProcessPath(DWORD pid, std::wstring& path)
    {
        HANDLE process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        );

        if (!process)
            return false;

        std::vector<wchar_t> buffer(32768);
        DWORD size = static_cast<DWORD>(buffer.size());

        const BOOL success = QueryFullProcessImageNameW(
            process,
            0,
            buffer.data(),
            &size
        );

        CloseHandle(process);

        if (!success || size == 0)
            return false;

        path.assign(buffer.data(), size);
        return true;
    }

    bool enumerateProcesses(ProcessMap& processes)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS,
            0
        );

        if (snapshot == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        if (!Process32FirstW(snapshot, &entry))
        {
            CloseHandle(snapshot);
            return false;
        }

        do
        {
            if (entry.th32ProcessID <= 4)
                continue;

            std::wstring path;

            if (getProcessPath(entry.th32ProcessID, path))
                processes[entry.th32ProcessID] = std::move(path);

        } while (Process32NextW(snapshot, &entry));

        CloseHandle(snapshot);
        return true;
    }

    int analyzeProcessPath(const std::wstring& originalPath,
        QString& details)
    {
        std::wstring path = originalPath;

        std::transform(
            path.begin(),
            path.end(),
            path.begin(),
            [](wchar_t c)
            {
                return static_cast<wchar_t>(std::towlower(c));
            }
        );

        if (path.find(L"\\appdata\\local\\temp\\") != std::wstring::npos
            || path.find(L"\\windows\\temp\\") != std::wstring::npos)
        {
            details = QStringLiteral(
                "Process launched from a temporary directory. "
                "This location alone does not prove malicious activity."
            );

            return 35;
        }

        if (path.find(L"\\downloads\\") != std::wstring::npos)
        {
            details = QStringLiteral(
                "Process launched from Downloads. "
                "Additional verification is recommended."
            );

            return 20;
        }

        details = QStringLiteral("No basic path-based risk indicators.");
        return 0;
    }
}

BehaviorMonitor::BehaviorMonitor(QObject* parent)
    : QObject(parent)
{
}

BehaviorMonitor::~BehaviorMonitor()
{
    stop();
}

bool BehaviorMonitor::active() const
{
    return m_active.load();
}

bool BehaviorMonitor::start()
{
    if (m_active.load())
        return true;

    if (m_worker.joinable())
        m_worker.join();

    m_active.store(true);

    try
    {
        m_worker = std::thread(
            [this]()
            {
                worker();
            }
        );
    }
    catch (...)
    {
        m_active.store(false);

        emit statusChanged(
            QStringLiteral("Behaviour Monitor: thread creation failed")
        );

        return false;
    }

    emit activeChanged();
    emit statusChanged(
        QStringLiteral("Behaviour Monitor: starting")
    );

    return true;
}

void BehaviorMonitor::stop()
{
    const bool wasActive = m_active.exchange(false);

    m_condition.notify_all();

    if (m_worker.joinable())
        m_worker.join();

    if (wasActive)
    {
        emit activeChanged();

        emit statusChanged(
            QStringLiteral("Behaviour Monitor: stopped")
        );
    }
}

void BehaviorMonitor::worker()
{
    ProcessMap previous;
    bool initialized = false;

    emit statusChanged(
        QStringLiteral("Behaviour Monitor: monitoring processes")
    );

    while (m_active.load())
    {
        ProcessMap current;

        if (enumerateProcesses(current))
        {
            if (initialized)
            {
                for (const auto& [pid, path] : current)
                {
                    const auto old = previous.find(pid);

                    if (old != previous.end() && old->second == path)
                        continue;

                    QString details;

                    const int score = analyzeProcessPath(
                        path,
                        details
                    );

                    const QString verdict = score > 0
                        ? QStringLiteral("REVIEW")
                        : QStringLiteral("OBSERVED");

                    emit processObserved(
                        static_cast<quint32>(pid),
                        QString::fromStdWString(path),
                        score,
                        verdict,
                        details
                    );
                }
            }

            previous = std::move(current);
            initialized = true;
        }

        std::unique_lock lock(m_mutex);

        m_condition.wait_for(
            lock,
            std::chrono::milliseconds(1500),
            [this]()
            {
                return !m_active.load();
            }
        );
    }
}
