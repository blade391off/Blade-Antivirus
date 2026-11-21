#include "file_watcher.h"

#include <windows.h>

#include <array>
#include <system_error>

namespace
{
    struct Handle
    {
        HANDLE value = INVALID_HANDLE_VALUE;

        ~Handle()
        {
            if (value != INVALID_HANDLE_VALUE)
                CloseHandle(value);
        }
    };

    std::wstring toWindowsPath(const std::filesystem::path& path)
    {
        std::wstring value = std::filesystem::path(path).make_preferred().wstring();

        if (value.rfind(L"\\\\?\\", 0) == 0)
            return value;

        if (value.rfind(L"\\\\", 0) == 0)
            return L"\\\\?\\UNC\\" + value.substr(2);

        if (value.size() >= 2 && value[1] == L':')
            return L"\\\\?\\" + value;

        return value;
    }
}

FileWatcher::~FileWatcher()
{
    stop();
}

bool FileWatcher::start(
    const std::vector<std::filesystem::path>& roots,
    Callback callback)
{
    stop();

    if (roots.empty() || !callback)
        return false;

    m_running = true;

    for (const auto& root : roots)
    {
        std::error_code error;

        if (!std::filesystem::is_directory(root, error))
            continue;

        m_threads.emplace_back(
            [this, root, callback]()
            {
                watchDirectory(root, callback);
            }
        );
    }

    if (m_threads.empty())
    {
        m_running = false;
        return false;
    }

    return true;
}

void FileWatcher::stop()
{
    if (!m_running.exchange(false))
        return;

    for (auto& thread : m_threads)
    {
        if (thread.joinable())
            CancelSynchronousIo(reinterpret_cast<HANDLE>(thread.native_handle()));
    }

    for (auto& thread : m_threads)
    {
        if (thread.joinable())
            thread.join();
    }

    m_threads.clear();
}

bool FileWatcher::running() const
{
    return m_running.load();
}

void FileWatcher::watchDirectory(
    std::filesystem::path directory,
    Callback callback)
{
    Handle handle;

    const std::wstring path = toWindowsPath(directory);

    handle.value = CreateFileW(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );

    if (handle.value == INVALID_HANDLE_VALUE)
        return;

    alignas(DWORD) std::array<BYTE, 64 * 1024> buffer{};

    while (m_running)
    {
        DWORD bytesReturned = 0;

        const BOOL success = ReadDirectoryChangesW(
            handle.value,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_CREATION,
            &bytesReturned,
            nullptr,
            nullptr
        );

        if (!success)
        {
            if (!m_running)
                break;

            continue;
        }

        if (bytesReturned == 0)
            continue;

        BYTE* position = buffer.data();

        while (position < buffer.data() + bytesReturned)
        {
            const auto* info =
                reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(position);

            if (info->Action == FILE_ACTION_ADDED
                || info->Action == FILE_ACTION_MODIFIED
                || info->Action == FILE_ACTION_RENAMED_NEW_NAME)
            {
                const std::wstring filename(
                    info->FileName,
                    info->FileNameLength / sizeof(WCHAR)
                );

                const auto fullPath = directory / filename;

                if (m_running)
                    callback(fullPath);
            }

            if (info->NextEntryOffset == 0)
                break;

            position += info->NextEntryOffset;
        }
    }
}
