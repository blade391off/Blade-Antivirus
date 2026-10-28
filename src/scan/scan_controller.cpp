
#include "scan_controller.h"
#include "scanner.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFileInfo>
#include <QMetaObject>
#include <QStringList>

#include <filesystem>
#include <utility>

ScanController::ScanController(QObject* parent)
    : QObject(parent)
{
}

ScanController::~ScanController()
{
    cancelScan();

    if (worker_.joinable())
        worker_.join();
}

bool ScanController::startScan(const QString& targetPath, bool recursive)
{
    if (running_.load())
        return false;

    if (worker_.joinable())
        worker_.join();

    const QFileInfo target(targetPath);

    if (targetPath.trimmed().isEmpty() || !target.exists())
    {
        emit statusChanged(QStringLiteral("Invalid scan path"));
        return false;
    }

    cancelled_.store(false);
    paused_.store(false);
    running_.store(true);

    worker_ = std::thread(
        [this, targetPath, recursive]()
        {
            runScan(targetPath, recursive);
        });

    return true;
}

void ScanController::pauseScan()
{
    if (!running_.load())
        return;

    paused_.store(true);
    publishStatus(QStringLiteral("Scan paused"));
}

void ScanController::resumeScan()
{
    paused_.store(false);
    pauseCondition_.notify_all();

    if (running_.load())
        publishStatus(QStringLiteral("Scanning"));
}

void ScanController::cancelScan()
{
    cancelled_.store(true);
    paused_.store(false);
    pauseCondition_.notify_all();
}

void ScanController::waitIfPaused()
{
    std::unique_lock<std::mutex> lock(pauseMutex_);

    pauseCondition_.wait(
        lock,
        [this]()
        {
            return !paused_.load() || cancelled_.load();
        });
}

void ScanController::publishStatus(const QString& status)
{
    QMetaObject::invokeMethod(
        this,
        [this, status]()
        {
            emit statusChanged(status);
        },
        Qt::QueuedConnection);
}

void ScanController::runScan(QString targetPath, bool recursive)
{
    int checkedFiles = 0;
    int threatsFound = 0;

    const auto finish =
        [this, &checkedFiles, &threatsFound]()
        {
            const bool wasCancelled = cancelled_.load();

            running_.store(false);

            const QString status = wasCancelled
                ? QStringLiteral("Scan cancelled")
                : QStringLiteral("Scan completed");

            QMetaObject::invokeMethod(
                this,
                [this, checkedFiles, threatsFound, wasCancelled, status]()
                {
                    emit statusChanged(status);
                    emit scanFinished(
                        checkedFiles,
                        threatsFound,
                        wasCancelled);
                },
                Qt::QueuedConnection);
        };

    QString databasePath = QDir(
        QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("database/hashes.txt"));

    if (!QFileInfo(databasePath).isFile())
    {
        const QString currentPath = QDir::current()
            .filePath(QStringLiteral("database/hashes.txt"));

        if (QFileInfo(currentPath).isFile())
            databasePath = currentPath;
        else
        {
            running_.store(false);
            publishStatus(
                QStringLiteral("Hash database not found: database/hashes.txt"));

            QMetaObject::invokeMethod(
                this,
                [this]()
                {
                    emit scanFinished(0, 0, false);
                },
                Qt::QueuedConnection);

            return;
        }
    }

    publishStatus(QStringLiteral("Preparing scanner"));

    Scanner scanner;

    const std::filesystem::path databaseFsPath(
        databasePath.toStdWString());

    if (!scanner.initialize(databaseFsPath))
    {
        running_.store(false);
        publishStatus(
            QStringLiteral("Failed to initialize scanner or load hash database"));

        QMetaObject::invokeMethod(
            this,
            [this]()
            {
                emit scanFinished(0, 0, false);
            },
            Qt::QueuedConnection);

        return;
    }

    if (cancelled_.load())
    {
        finish();
        return;
    }

    publishStatus(
        QStringLiteral("Scanner ready — database entries: %1")
        .arg(static_cast<qulonglong>(scanner.databaseSize())));

    QStringList files;
    const QFileInfo target(targetPath);

    if (target.isFile())
    {
        files.append(target.absoluteFilePath());
    }
    else if (target.isDir())
    {
        const auto flags = recursive
            ? QDirIterator::Subdirectories
            : QDirIterator::NoIteratorFlags;

        QDirIterator iterator(
            target.absoluteFilePath(),
            QDir::Files | QDir::NoDotAndDotDot,
            flags);

        while (iterator.hasNext())
        {
            if (cancelled_.load())
                break;

            files.append(iterator.next());
        }
    }

    if (cancelled_.load())
    {
        finish();
        return;
    }

    const int totalFiles = files.size();

    if (totalFiles == 0)
    {
        publishStatus(QStringLiteral("No files found"));
        finish();
        return;
    }

    publishStatus(QStringLiteral("Scanning"));

    for (const QString& filePath : files)
    {
        if (cancelled_.load())
            break;

        waitIfPaused();

        if (cancelled_.load())
            break;

        const QString fullName = QFileInfo(filePath).fileName();

        const QString displayName = fullName.size() > 32
            ? fullName.left(29) + QChar(0x2026)
            : fullName;

        const std::filesystem::path fileFsPath(
            filePath.toStdWString());

        const ScanResult result = scanner.scan(fileFsPath);
        const QString verdict = QString::fromStdString(result.verdict);

        QString details;

        if (verdict == QStringLiteral("MALICIOUS"))
        {
            ++threatsFound;

            details = QStringLiteral("SHA-256 match: ")
                + QString::fromStdString(result.sha256);
        }
        else if (verdict == QStringLiteral("CLEAN"))
        {
            details = result.isPE
                ? QStringLiteral(
                    "PE file checked; no hash signature match")
                : QStringLiteral(
                    "No hash signature match");
        }
        else if (verdict == QStringLiteral("SKIPPED"))
        {
            details = QStringLiteral(
                "Skipped: cloud-only, unsupported file type, or file exceeds size limit");
        }
        else
        {
            details = QStringLiteral("File check failed");

            if (result.winError != 0)
            {
                details += QStringLiteral(" (Windows error %1)")
                    .arg(result.winError);
            }
        }

        ++checkedFiles;

        const int percentage = checkedFiles * 100 / totalFiles;

        QMetaObject::invokeMethod(
            this,
            [this, displayName, verdict, details,
            checkedFiles, totalFiles, percentage, filePath]()
            {
                emit fileChecked(displayName, verdict, details);

                emit progressChanged(
                    percentage,
                    checkedFiles,
                    totalFiles,
                    filePath);
            },
            Qt::QueuedConnection);
    }

    finish();
}
