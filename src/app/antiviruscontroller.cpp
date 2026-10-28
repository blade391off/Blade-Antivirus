#include "antiviruscontroller.h"
#include "../scanner/scanner.h"
#include "../updater/updater.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>
#include <QUrl>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <exception>
#include <filesystem>
#include <string>

namespace
{
    constexpr int kAutoUpdateIntervalMs = (1 * 60 + 59) * 60 * 1000; // 1 h 59 min
    constexpr int kFirstUpdateDelayMs = 30 * 1000;      // let the network come up
    constexpr int kRetryBaseDelayMs = 10 * 60 * 1000;   // doubles per failure

    // The updated database lives in the per-user data dir (writable, so the
    // updater works even when the app sits in Program Files). A copy shipped
    // next to the exe is only a fallback until the first update.
    // The current working directory is never used.
    QString dataDir()
    {
        return QStandardPaths::writableLocation(
                   QStandardPaths::AppLocalDataLocation)
            + "/database";
    }

    QString bundledDir()
    {
        return QCoreApplication::applicationDirPath() + "/database";
    }

    QString findDatabase()
    {
        QStringList candidates = {
            dataDir() + "/hashes.txt",
            bundledDir() + "/hashes.txt"
        };

#if defined(BLADE_SOURCE_DIR) && !defined(QT_NO_DEBUG)
        candidates << QStringLiteral(BLADE_SOURCE_DIR) + "/database/hashes.txt";
#endif

        for (const QString& path : candidates) {
            const QFileInfo info(path);

            if (info.isFile())
                return info.absoluteFilePath();
        }

        return {};
    }

    // Lowers CPU, I/O and memory priority of the calling thread so scans and
    // updates do not slow the machine down. Restored on scope exit.
    class BackgroundMode
    {
    public:
        BackgroundMode()
            : m_active(SetThreadPriority(
                  GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) != 0)
        {
        }

        ~BackgroundMode()
        {
            if (m_active) {
                SetThreadPriority(
                    GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
            }
        }

        BackgroundMode(const BackgroundMode&) = delete;
        BackgroundMode& operator=(const BackgroundMode&) = delete;

    private:
        bool m_active;
    };

    // Removes duplicates and roots nested inside other roots,
    // so no file is scanned twice and no path set has to be kept in memory.
    QStringList normalizeRoots(const QStringList& input)
    {
        QStringList roots;

        for (const QString& folder : input) {
            const QString canonical = QFileInfo(folder).canonicalFilePath();

            if (!canonical.isEmpty()
                && !roots.contains(canonical, Qt::CaseInsensitive)) {
                roots.append(canonical);
            }
        }

        QStringList result;

        for (qsizetype i = 0; i < roots.size(); ++i) {
            bool nested = false;

            for (qsizetype j = 0; j < roots.size() && !nested; ++j) {
                if (i == j)
                    continue;

                const QString prefix = roots[j].endsWith('/')
                    ? roots[j]
                    : roots[j] + '/';

                nested = roots[i].startsWith(prefix, Qt::CaseInsensitive);
            }

            if (!nested)
                result.append(roots[i]);
        }

        return result;
    }
}

AntivirusController::AntivirusController(QObject* parent)
    : QObject(parent)
    , m_updateTimer(this)
{
    m_updateTimer.setInterval(kAutoUpdateIntervalMs);
    m_updateTimer.setTimerType(Qt::VeryCoarseTimer);

    connect(&m_updateTimer, &QTimer::timeout, this, [this]() {
        startUpdate(false);
    });

    m_updateTimer.start();

    // First check shortly after launch (also right after login via autostart).
    QTimer::singleShot(kFirstUpdateDelayMs, this, [this]() {
        startUpdate(false);
    });

    // Failed update: retry sooner than the regular cycle, with back-off
    // (10, 20, 40, 80 min ...) so a dead source is not hammered.
    connect(this, &AntivirusController::updateFinished, this, [this](bool ok) {
        if (ok) {
            m_updateFailures = 0;
            return;
        }

        ++m_updateFailures;

        const int shift = std::min(m_updateFailures - 1, 4);
        const int delay = std::min(kRetryBaseDelayMs << shift, kAutoUpdateIntervalMs);

        QTimer::singleShot(delay, this, [this]() { startUpdate(false); });
    });
}

AntivirusController::~AntivirusController()
{
    // Without this, closing the window during a full scan hangs until it ends.
    m_stopRequested.store(true);

    if (m_worker.joinable())
        m_worker.join();

    // An update in flight is bounded by the WinHTTP timeouts.
    if (m_updateWorker.joinable())
        m_updateWorker.join();
}

bool AntivirusController::scanning() const
{
    return m_scanning.load();
}

// QUICK SCAN: Desktop, Documents, Downloads.
void AntivirusController::startQuickScan()
{
    if (m_scanning.load()) {
        emit statusChanged("A scan is already running.");
        return;
    }

    const QStringList folders = {
        QStandardPaths::writableLocation(QStandardPaths::DesktopLocation),
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation),
        QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)
    };

    QStringList existingFolders;

    for (const QString& folder : folders) {
        if (!folder.isEmpty()
            && QFileInfo(folder).isDir()
            && !existingFolders.contains(folder)) {
            existingFolders.append(folder);
        }
    }

    if (existingFolders.isEmpty()) {
        emit statusChanged("Quick scan: no user folders were found.");
        return;
    }

    startScan(existingFolders);
}

// FULL SCAN: all fixed drives.
void AntivirusController::startFullScan()
{
    if (m_scanning.load()) {
        emit statusChanged("A scan is already running.");
        return;
    }

    QStringList folders;

    for (const QFileInfo& drive : QDir::drives()) {
        const QString root = drive.absoluteFilePath();
        const auto* drivePath = reinterpret_cast<LPCWSTR>(root.utf16());

        if (GetDriveTypeW(drivePath) == DRIVE_FIXED
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

// CUSTOM SCAN: one selected folder.
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
    startUpdate(true);
}

// manual = button/tray click (reports progress and "already running");
// automatic runs stay quiet while a scan is showing its own status.
void AntivirusController::startUpdate(bool manual)
{
    if (m_updating.exchange(true)) {
        if (manual)
            emit statusChanged("An update is already running.");
        return;
    }

    if (m_updateWorker.joinable())
        m_updateWorker.join();

    const QString dir = dataDir();

    if (manual)
        emit statusChanged("Checking for updates...");

    m_updateWorker = std::thread(
        [this, dir, manual]() {
            BackgroundMode background;

            std::string report;
            bool ok = false;

            try {
                QDir().mkpath(dir);

                const auto toPath = [](const QString& p) {
                    return std::filesystem::path(p.toStdWString());
                };

                // dir/sources.txt (one https URL per line) overrides the
                // built-in list; see Updater::defaultSources().
                const std::vector<std::string> sources =
                    Updater::loadSources(toPath(dir + "/sources.txt"));

                Updater updater;

                ok = updater.updateHashes(
                    toPath(dir + "/hashes.txt"),
                    toPath(dir + "/update_state.txt"),
                    sources,
                    report,
                    false,
                    [this, manual](const std::string& message) {
                        if (manual)
                            emit statusChanged(QString::fromStdString(message));
                    });
            }
            catch (const std::exception& e) {
                report = std::string("Update crashed: ") + e.what();
            }
            catch (...) {
                report = "Update crashed: unknown error";
            }

            QString text = QString::fromStdString(report).trimmed();
            text.remove('\r');
            text.replace('\n', " | ");

            m_updating.store(false);

            if (manual || !m_scanning.load()) {
                emit statusChanged(
                    QString(ok ? "Update: %1" : "Update problem: %1").arg(text));
            }

            emit updateFinished(ok);
        }
    );
}

// COMMON SCANNING ENGINE
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
        emit statusChanged("Hash database not found. Run \"Check for updates\" or put database/hashes.txt next to the exe.");
        return;
    }

    const QStringList roots = normalizeRoots(folders);
    const QString cachePath = dataDir() + "/scan_cache.bin";

    if (roots.isEmpty()) {
        m_scanning.store(false);

        emit scanningChanged();
        emit statusChanged("Nothing to scan.");
        return;
    }

    emit scanningChanged();
    emit statusChanged("Preparing scanner...");

    m_worker = std::thread(
        [this, roots, databasePath, cachePath]() {
            BackgroundMode background;

            int scanned = 0;
            int detected = 0;
            int suspicious = 0;
            int errors = 0;
            int skipped = 0;
            bool initFailed = false;
            QString failure;

            QElapsedTimer totalTimer;
            totalTimer.start();

            // An exception escaping a std::thread calls std::terminate().
            try {
                Scanner scanner;

                if (!scanner.initialize(
                        std::filesystem::path(databasePath.toStdWString()),
                        std::filesystem::path(cachePath.toStdWString()))) {
                    initFailed = true;
                }
                else {
                    emit statusChanged("Scanning files...");

                    QElapsedTimer progressTimer;
                    progressTimer.start();

                    for (const QString& root : roots) {
                        if (m_stopRequested.load())
                            break;

                        // Hidden and System are included on purpose:
                        // malware loves hidden/system attributes.
                        QDirIterator it(
                            root,
                            QDir::Files
                            | QDir::Hidden
                            | QDir::System
                            | QDir::NoDotAndDotDot,
                            QDirIterator::Subdirectories
                        );

                        while (it.hasNext()) {
                            if (m_stopRequested.load())
                                break;

                            const QString path = it.next();
                            ++scanned;

                            const ScanResult result = scanner.scan(
                                std::filesystem::path(path.toStdWString()));
                            const QString verdict =
                                QString::fromStdString(result.verdict);

                            // Only report interesting files. Emitting a queued
                            // signal per file floods the GUI event loop on a full scan.
                            if (verdict == "MALICIOUS") {
                                ++detected;
                                emit fileScanned(
                                    path,
                                    verdict,
                                    QString::fromStdString(result.sha256),
                                    "Known malware: SHA-256 is in the blocklist");
                            }
                            else if (verdict == "SUSPICIOUS") {
                                ++suspicious;
                                emit fileScanned(
                                    path,
                                    verdict,
                                    QString::fromStdString(result.sha256),
                                    QString::fromStdString(result.details));
                            }
                            else if (verdict == "ERROR") {
                                // Locked/system files are normal on a full scan;
                                // they are only counted, not reported one by one.
                                ++errors;
                            }
                            else if (verdict == "SKIPPED") {
                                ++skipped;
                            }

                            if (progressTimer.hasExpired(250)) {
                                emit scanProgress(
                                    QString("Checked %1 files...").arg(scanned));
                                emit scanStats(
                                    scanned, detected, suspicious, errors, skipped,
                                    totalTimer.elapsed(),
                                    QDir::toNativeSeparators(path));
                                progressTimer.restart();
                            }
                        }
                    }

                    // Remember clean files so the next scan is much faster.
                    scanner.saveCache();
                }
            }
            catch (const std::exception& e) {
                ++errors;
                failure = QString("Scan aborted: %1").arg(QString::fromUtf8(e.what()));
                qCritical() << "[BladeAntivirus] scan thread exception:" << e.what();
            }
            catch (...) {
                ++errors;
                failure = "Scan aborted: unknown error";
                qCritical() << "[BladeAntivirus] scan thread: unknown exception";
            }

            if (initFailed)
                failure = "Could not load the hash database (missing or empty). Run \"Check for updates\".";

            const bool stopped = m_stopRequested.load();
            m_scanning.store(false);
            m_stopRequested.store(false);

            emit scanningChanged();

            if (initFailed) {
                emit statusChanged(failure);
                emit scanFinished(0, 0, 1);
                emit scanSummary(0, 0, 0, 1, 0, totalTimer.elapsed(), false, failure);
                return;
            }

            // Tray notification and status line count both kinds as "threats".
            emit scanFinished(scanned, detected + suspicious, errors);
            emit scanSummary(
                scanned, detected, suspicious, errors, skipped,
                totalTimer.elapsed(), stopped, failure);

            emit statusChanged(
                QString("Scan %1. Checked: %2, malicious: %3, suspicious: %4, unreadable: %5, skipped: %6")
                .arg(stopped ? "stopped" : "finished")
                .arg(scanned)
                .arg(detected)
                .arg(suspicious)
                .arg(errors)
                .arg(skipped)
            );
        }
    );
}
