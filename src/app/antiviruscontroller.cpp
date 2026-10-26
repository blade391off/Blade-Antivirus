#include "antiviruscontroller.h"

#include "../scanner/scanner.h"
#include "../updater/updater.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QStandardPaths>
#include <QStringList>
#include <QUrl>

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <exception>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <filesystem>

namespace
{
    QString dataDir()
    {
        return QStandardPaths::writableLocation(
            QStandardPaths::AppLocalDataLocation)
            + "/database";
    }

    QString bundledDir()
    {
        return QCoreApplication::applicationDirPath()
            + "/database";
    }

    QString findDatabase()
    {
        const QStringList candidates = {
            dataDir() + "/hashes.txt",
            bundledDir() + "/hashes.txt"
        };

        for (const QString& path : candidates) {
            const QFileInfo info(path);

            if (info.isFile())
                return info.absoluteFilePath();
        }

        return {};
    }

    std::filesystem::path toNativePath(const QString& path)
    {
        return std::filesystem::path(path.toStdWString());
    }

    class BackgroundMode
    {
    public:
        BackgroundMode()
        {
            m_active = SetThreadPriority(
                GetCurrentThread(),
                THREAD_MODE_BACKGROUND_BEGIN) != 0;
        }

        ~BackgroundMode()
        {
            if (m_active) {
                SetThreadPriority(
                    GetCurrentThread(),
                    THREAD_MODE_BACKGROUND_END);
            }
        }

        BackgroundMode(const BackgroundMode&) = delete;
        BackgroundMode& operator=(const BackgroundMode&) = delete;

    private:
        bool m_active = false;
    };

    QStringList normalizeRoots(const QStringList& input)
    {
        QStringList roots;

        for (const QString& folder : input) {
            const QString absolute =
                QDir::cleanPath(QFileInfo(folder).absoluteFilePath());

            if (QFileInfo(absolute).isDir()
                && !roots.contains(absolute, Qt::CaseInsensitive)) {
                roots.append(absolute);
            }
        }

        QStringList result;

        for (qsizetype i = 0; i < roots.size(); ++i) {
            bool nested = false;

            for (qsizetype j = 0;
                j < roots.size() && !nested;
                ++j) {
                if (i == j)
                    continue;

                QString parent =
                    QDir::fromNativeSeparators(roots[j]);
                QString child =
                    QDir::fromNativeSeparators(roots[i]);

                if (!parent.endsWith('/'))
                    parent += '/';

                nested = child.startsWith(
                    parent, Qt::CaseInsensitive);
            }

            if (!nested)
                result.append(roots[i]);
        }

        return result;
    }
}

AntivirusController::AntivirusController(QObject* parent)
    : QObject(parent)
{
}

AntivirusController::~AntivirusController()
{
    m_stopRequested.store(true);

    if (m_worker.joinable())
        m_worker.join();

    if (m_updateWorker.joinable())
        m_updateWorker.join();
}

bool AntivirusController::scanning() const
{
    return m_scanning.load();
}

void AntivirusController::startQuickScan()
{
    if (m_scanning.load()) {
        emit statusChanged("A scan is already running.");
        return;
    }

    const QStringList folders = {
        QStandardPaths::writableLocation(
            QStandardPaths::DesktopLocation),
        QStandardPaths::writableLocation(
            QStandardPaths::DocumentsLocation),
        QStandardPaths::writableLocation(
            QStandardPaths::DownloadLocation)
    };

    QStringList existingFolders;

    for (const QString& folder : folders) {
        if (!folder.isEmpty()
            && QFileInfo(folder).isDir()
            && !existingFolders.contains(
                folder, Qt::CaseInsensitive)) {
            existingFolders.append(folder);
        }
    }

    if (existingFolders.isEmpty()) {
        emit statusChanged(
            "Quick scan: no user folders were found.");
        return;
    }

    startScan(existingFolders);
}

void AntivirusController::startFullScan()
{
    if (m_scanning.load()) {
        emit statusChanged("A scan is already running.");
        return;
    }

    QStringList folders;

    for (const QFileInfo& drive : QDir::drives()) {
        const QString root = drive.absoluteFilePath();

        if (GetDriveTypeW(
            reinterpret_cast<LPCWSTR>(root.utf16()))
            == DRIVE_FIXED
            && QFileInfo(root).isDir()) {
            folders.append(root);
        }
    }

    if (folders.isEmpty()) {
        emit statusChanged("No fixed drives found.");
        return;
    }

    startScan(folders);
}

void AntivirusController::startCustomScan(const QUrl& folderUrl)
{
    if (m_scanning.load()) {
        emit statusChanged("A scan is already running.");
        return;
    }

    const QString folder = folderUrl.toLocalFile();

    if (folder.isEmpty() || !QFileInfo(folder).isDir()) {
        emit statusChanged("Invalid folder selected.");
        return;
    }

    startScan({ folder });
}

void AntivirusController::stopScan()
{
    if (!m_scanning.load()) {
        emit statusChanged("No active scan to stop.");
        return;
    }

    m_stopRequested.store(true);
    emit statusChanged("Stopping scan...");
}

void AntivirusController::checkUpdates()
{
    if (m_updating.exchange(true)) {
        emit statusChanged("An update is already running.");
        return;
    }

    if (m_updateWorker.joinable())
        m_updateWorker.join();

    const QString dir = dataDir();

    emit statusChanged("Checking for updates...");

    m_updateWorker = std::thread([this, dir]() {
        BackgroundMode background;

        std::string report;
        bool ok = false;

        try {
            if (!QDir().mkpath(dir)) {
                throw std::runtime_error(
                    "Could not create the database directory.");
            }

            const auto databasePath =
                toNativePath(dir + "/hashes.txt");

            const auto statePath =
                toNativePath(dir + "/update_state.txt");

            const auto sourcesPath =
                toNativePath(dir + "/sources.txt");

            const std::vector<std::string> sources =
                Updater::loadSources(sourcesPath);

            Updater updater;

            ok = updater.updateHashes(
                databasePath,
                statePath,
                sources,
                report,
                false,
                [this](const std::string& message) {
                    emit statusChanged(
                        QString::fromStdString(message));
                });
        }
        catch (const std::exception& e) {
            report = std::string("Update failed: ") + e.what();
        }
        catch (...) {
            report = "Update failed: unknown error";
        }

        QString message =
            QString::fromStdString(report).trimmed();

        message.remove('\r');
        message.replace('\n', " | ");

        m_updating.store(false);

        emit statusChanged(
            QString(ok ? "Update finished: %1"
                : "Update problem: %1")
            .arg(message));
        });
}

void AntivirusController::startScan(const QStringList& folders)
{
    if (m_scanning.exchange(true)) {
        emit statusChanged("A scan is already running.");
        return;
    }

    if (m_worker.joinable())
        m_worker.join();

    m_stopRequested.store(false);

    const QString databasePath = findDatabase();

    if (databasePath.isEmpty()) {
        m_scanning.store(false);
        emit scanningChanged();
        emit statusChanged(
            "Hash database not found. Run Check for updates "
            "or place database/hashes.txt next to the executable.");
        return;
    }

    const QStringList roots = normalizeRoots(folders);

    if (roots.isEmpty()) {
        m_scanning.store(false);
        emit scanningChanged();
        emit statusChanged("Nothing to scan.");
        return;
    }

    emit scanningChanged();
    emit statusChanged("Preparing scanner...");

    m_worker = std::thread([this, roots, databasePath]() {
        BackgroundMode background;

        int scanned = 0;
        int detected = 0;
        int errors = 0;
        int skipped = 0;
        bool initFailed = false;

        try {
            Scanner scanner;

            if (!scanner.initialize(toNativePath(databasePath))) {
                initFailed = true;
            }
            else {
                emit statusChanged("Scanning files...");

                QElapsedTimer progressTimer;
                progressTimer.start();

                for (const QString& root : roots) {
                    if (m_stopRequested.load())
                        break;

                    QDirIterator it(
                        root,
                        QDir::Files
                        | QDir::Hidden
                        | QDir::System
                        | QDir::NoDotAndDotDot,
                        QDirIterator::Subdirectories);

                    while (it.hasNext()) {
                        if (m_stopRequested.load())
                            break;

                        const QString path = it.next();
                        ++scanned;

                        const ScanResult result =
                            scanner.scan(toNativePath(path));

                        const QString verdict =
                            QString::fromStdString(result.verdict);

                        if (verdict == "MALICIOUS") {
                            ++detected;

                            emit fileScanned(
                                path,
                                verdict,
                                QString::fromStdString(result.sha256));
                        }
                        else if (verdict == "ERROR") {
                            ++errors;
                            emit fileScanned(
                                path, verdict, QString());
                        }
                        else if (verdict == "SKIPPED") {
                            ++skipped;
                        }

                        if (progressTimer.hasExpired(250)) {
                            emit scanProgress(
                                QString("Checked %1 files...")
                                .arg(scanned));
                            progressTimer.restart();
                        }
                    }
                }
            }
        }
        catch (const std::exception& e) {
            ++errors;
            qCritical() << "[BladeAntivirus] Scan exception:"
                << e.what();
        }
        catch (...) {
            ++errors;
            qCritical() << "[BladeAntivirus] Unknown scan exception";
        }

        const bool stopped = m_stopRequested.load();

        m_scanning.store(false);
        m_stopRequested.store(false);

        emit scanningChanged();

        if (initFailed) {
            emit statusChanged(
                "Could not load the hash database (missing or empty).");
            emit scanFinished(0, 0, 1);
            return;
        }

        emit scanFinished(scanned, detected, errors);

        emit statusChanged(
            QString("Scan %1. Checked: %2, detections: %3, "
                "errors: %4, skipped: %5")
            .arg(stopped ? "stopped" : "finished")
            .arg(scanned)
            .arg(detected)
            .arg(errors)
            .arg(skipped));
        });
}
