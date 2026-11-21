#include "antiviruscontroller.h"
#include "../database/database_locator.h"
#include "../scanner/scanner.h"
#include "../updater/updater.h"

#include <QByteArray>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QDirIterator>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>
#include <QStandardPaths>
#include <QStringList>
#include <QTextStream>
#include <QUrl>

#include <windows.h>
#include <tlhelp32.h>

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
        return QString::fromStdWString(
            blade::database::userDatabaseDir().wstring());
    }

    QString findDatabase()
    {
        return QString::fromStdWString(
            blade::database::locateHashes().wstring());
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
    , m_scheduledScanTimer(this)
{
    // A database written by an older build lived one level higher; move it
    // before the first read so an upgrade does not look like "not found".
    blade::database::migrateLegacyDatabase();

    m_updateTimer.setInterval(kAutoUpdateIntervalMs);
    m_updateTimer.setTimerType(Qt::VeryCoarseTimer);

    connect(&m_updateTimer, &QTimer::timeout, this, [this]() {
        startUpdate(false);
    });

    m_updateTimer.start();

    // Report a missing database right away instead of waiting for the first
    // scan attempt to fail. Queued so the QML side is already connected.
    QTimer::singleShot(0, this, [this]() { publishDatabaseStatus(); });

    // Load persisted settings (exclusions, scheduled scan) and wire the
    // scheduled-scan timer to run a full scan.
    loadSettings();

    connect(&m_scheduledScanTimer, &QTimer::timeout, this, [this]() {
        if (!m_scanning.load())
            startFullScan();
    });

    // First check shortly after launch (also right after login via autostart).
    QTimer::singleShot(kFirstUpdateDelayMs, this, [this]() {
        startUpdate(false);
    });

    // Failed update: retry sooner than the regular cycle, with back-off
    // (10, 20, 40, 80 min ...) so a dead source is not hammered.
    connect(this, &AntivirusController::updateFinished, this, [this](bool ok) {
        if (ok) {
            m_updateFailures = 0;

            // The first successful update turns a silent "missing database"
            // into a working install; reflect that in the UI.
            if (!m_databaseAvailable)
                publishDatabaseStatus();

            return;
        }

        ++m_updateFailures;

        const int shift = std::min(m_updateFailures - 1, 4);
        const int delay = std::min(kRetryBaseDelayMs << shift, kAutoUpdateIntervalMs);

        QTimer::singleShot(delay, this, [this]() { startUpdate(false); });
    });
}

bool AntivirusController::databaseAvailable() const
{
    return m_databaseAvailable;
}

void AntivirusController::publishDatabaseStatus()
{
    const bool available = !findDatabase().isEmpty();

    if (available != m_databaseAvailable) {
        m_databaseAvailable = available;
        emit databaseAvailableChanged();
    }

    if (available) {
        emit statusChanged(QStringLiteral("Protection ready"));
        return;
    }

    emit statusChanged(QStringLiteral(
        "Detection database is missing. Run \"Check for updates\" "
        "to download it."));
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

    m_lastScanResults.clear();

    const QString databasePath = findDatabase();

    if (databasePath.isEmpty()) {
        m_scanning.store(false);

        emit scanningChanged();
        publishDatabaseStatus();
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
            QString initDetail;
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
                    initDetail = QString::fromStdString(scanner.lastError());
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

                            if (isExcluded(path)) {
                                ++skipped;
                                continue;
                            }

                            ++scanned;

                            const ScanResult result = scanner.scan(
                                std::filesystem::path(path.toStdWString()));
                            const QString verdict =
                                QString::fromStdString(result.verdict);

                            // Remember for export / history.
                            ScanEntry entry;
                            entry.path = path;
                            entry.verdict = verdict;
                            entry.sha256 = QString::fromStdString(result.sha256);
                            entry.details = QString::fromStdString(result.details);
                            m_lastScanResults.push_back(entry);

                            // Only report interesting files. Emitting a queued
                            // signal per file floods the GUI event loop on a full scan.
                            if (verdict == "MALICIOUS") {
                                ++detected;
                                emit fileScanned(
                                    path,
                                    verdict,
                                    QString::fromStdString(result.sha256),
                                    result.details.empty()
                                        ? QStringLiteral("Known malware: SHA-256 is in the blocklist")
                                        : QString::fromStdString(result.details));

                                emit threatDetected(
                                    path, verdict,
                                    result.details.empty()
                                        ? QStringLiteral("Known malware: SHA-256 is in the blocklist")
                                        : QString::fromStdString(result.details));
                            }
                            else if (verdict == "SUSPICIOUS") {
                                ++suspicious;
                                emit fileScanned(
                                    path,
                                    verdict,
                                    QString::fromStdString(result.sha256),
                                    QString::fromStdString(result.details));

                                emit threatDetected(
                                    path, verdict,
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

                    appendScanHistory(
                        scanned, detected, suspicious, errors, skipped,
                        totalTimer.elapsed());
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

            if (initFailed) {
                failure = initDetail.isEmpty()
                    ? QStringLiteral("Scanner initialization failed. Run \"Check for updates\".")
                    : QStringLiteral("Scanner initialization failed: %1").arg(initDetail);
            }

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
// ===================== NEW FEATURES =====================

QStringList AntivirusController::exclusions() const { return m_exclusions; }

void AntivirusController::addExclusion(const QString& path) {
    const QString canonical = QFileInfo(path).canonicalFilePath();
    if (canonical.isEmpty() || m_exclusions.contains(canonical, Qt::CaseInsensitive)) return;
    m_exclusions.append(canonical);
    saveSettings();
    emit exclusionsChanged();
}

void AntivirusController::removeExclusion(const QString& path) {
    m_exclusions.removeAll(path);
    saveSettings();
    emit exclusionsChanged();
}

void AntivirusController::clearExclusions() {
    m_exclusions.clear();
    saveSettings();
    emit exclusionsChanged();
}

bool AntivirusController::isExcluded(const QString& path) const {
    for (const QString& exclusion : m_exclusions)
        if (path.startsWith(exclusion, Qt::CaseInsensitive)) return true;
    return false;
}

void AntivirusController::startPathsScan(const QStringList& paths) { startScan(paths); }

void AntivirusController::scanRunningProcesses() {
    QStringList processPaths;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == 0) continue;
            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
            if (!process) continue;
            wchar_t buffer[MAX_PATH]; DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(process, 0, buffer, &size)) {
                const QString path = QString::fromWCharArray(buffer, static_cast<int>(size));
                if (!path.isEmpty() && !processPaths.contains(path, Qt::CaseInsensitive))
                    processPaths.append(path);
            }
            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    if (!processPaths.isEmpty()) startScan(processPaths);
}

QString AntivirusController::quarantineRoot() const { return dataDir() + "/quarantine"; }

bool AntivirusController::quarantineFile(const QString& path) {
    QFileInfo info(path);
    if (!info.exists() || !info.isFile()) return false;
    const QString id = QString::number(QDateTime::currentMSecsSinceEpoch());
    const QString dir = quarantineRoot() + "/" + id;
    QDir().mkpath(dir);
    const QString destination = dir + "/" + info.fileName();
    if (!QFile::rename(path, destination)) return false;
    QJsonObject manifest;
    manifest["id"] = id; manifest["originalPath"] = path;
    manifest["fileName"] = info.fileName();
    manifest["quarantinedAt"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    manifest["size"] = static_cast<qint64>(info.size());
    QFile mf(dir + "/manifest.json");
    if (mf.open(QIODevice::WriteOnly | QIODevice::Text)) {
        mf.write(QJsonDocument(manifest).toJson(QJsonDocument::Indented));
        mf.close();
    }
    return true;
}

bool AntivirusController::restoreQuarantined(const QString& id) {
    const QString dir = quarantineRoot() + "/" + id;
    QFile mf(dir + "/manifest.json");
    if (!mf.open(QIODevice::ReadOnly)) return false;
    const QJsonDocument doc = QJsonDocument::fromJson(mf.readAll());
    mf.close();
    const QString originalPath = doc.object().value("originalPath").toString();
    const QString fileName = doc.object().value("fileName").toString();
    if (originalPath.isEmpty() || fileName.isEmpty()) return false;
    const QString source = dir + "/" + fileName;
    if (!QFile::exists(source)) return false;
    QDir().mkpath(QFileInfo(originalPath).absolutePath());
    if (!QFile::rename(source, originalPath)) return false;
    QDir(dir).removeRecursively();
    return true;
}

bool AntivirusController::deleteQuarantined(const QString& id) {
    const QString dir = quarantineRoot() + "/" + id;
    if (!QDir(dir).exists()) return false;
    return QDir(dir).removeRecursively();
}

QStringList AntivirusController::quarantinedFiles() const {
    QStringList result;
    QDir root(quarantineRoot());
    if (!root.exists()) return result;
    for (const QString& id : root.entryList(QDir::Dirs | QDir::NoDotAndDotDot)) {
        QFile mf(root.filePath(id) + "/manifest.json");
        if (!mf.open(QIODevice::ReadOnly)) continue;
        const QJsonDocument doc = QJsonDocument::fromJson(mf.readAll());
        mf.close();
        const QJsonObject o = doc.object();
        result.append(QString("%1|%2|%3").arg(id, o.value("fileName").toString(), o.value("originalPath").toString()));
    }
    return result;
}

void AntivirusController::setScheduledScanEnabled(bool enabled) {
    m_scheduledScanEnabled = enabled;
    if (enabled) {
        if (!m_scheduledScanTimer.isActive())
            m_scheduledScanTimer.start(m_scheduledScanIntervalMinutes * 60 * 1000);
    } else {
        m_scheduledScanTimer.stop();
    }
    saveSettings();
    emit scheduledScanEnabledChanged();
}

void AntivirusController::setScheduledScanIntervalMinutes(int minutes) {
    if (minutes < 5) minutes = 5;
    m_scheduledScanIntervalMinutes = minutes;
    if (m_scheduledScanTimer.isActive())
        m_scheduledScanTimer.setInterval(minutes * 60 * 1000);
    saveSettings();
    emit scheduledScanIntervalMinutesChanged();
}

bool AntivirusController::scheduledScanEnabled() const { return m_scheduledScanEnabled; }
int AntivirusController::scheduledScanIntervalMinutes() const { return m_scheduledScanIntervalMinutes; }

bool AntivirusController::exportLastScanReport(const QString& filePath) const {
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) return false;
    QTextStream stream(&file);
    stream << "path,verdict,sha256,details\n";
    for (const ScanEntry& entry : m_lastScanResults) {
        stream << "\"" << entry.path << "\"," << entry.verdict << "," << entry.sha256 << ",\"" << entry.details << "\"\n";
    }
    file.close();
    return true;
}

QStringList AntivirusController::recentScanHistory() const {
    QFile file(dataDir() + "/scan_history.json");
    if (!file.open(QIODevice::ReadOnly)) return {};
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    QStringList result;
    for (const QJsonValue& v : doc.array()) {
        const QJsonObject o = v.toObject();
        result.append(QString("%1 | %2 files | %3 malicious | %4 suspicious")
            .arg(o.value("finishedAt").toString())
            .arg(o.value("scanned").toInt())
            .arg(o.value("detected").toInt())
            .arg(o.value("suspicious").toInt()));
    }
    return result;
}

void AntivirusController::appendScanHistory(int scanned, int detected, int suspicious, int errors, int skipped, qint64 elapsedMs) {
    QFile file(dataDir() + "/scan_history.json");
    QJsonArray array;
    if (file.open(QIODevice::ReadOnly)) { array = QJsonDocument::fromJson(file.readAll()).array(); file.close(); }
    QJsonObject entry;
    entry["finishedAt"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
    entry["scanned"] = scanned; entry["detected"] = detected;
    entry["suspicious"] = suspicious; entry["errors"] = errors;
    entry["skipped"] = skipped; entry["elapsedMs"] = elapsedMs;
    array.append(entry);
    while (array.size() > 50) array.removeFirst();
    if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        file.write(QJsonDocument(array).toJson(QJsonDocument::Indented));
        file.close();
    }
}

void AntivirusController::loadSettings() {
    QSettings settings("BladeAntivirus", "BladeAntivirus");
    m_exclusions = settings.value("exclusions").toStringList();
    m_scheduledScanEnabled = settings.value("scheduledScanEnabled", false).toBool();
    m_scheduledScanIntervalMinutes = settings.value("scheduledScanIntervalMinutes", 60).toInt();
    if (m_scheduledScanEnabled) {
        m_scheduledScanTimer.setInterval(m_scheduledScanIntervalMinutes * 60 * 1000);
        m_scheduledScanTimer.setTimerType(Qt::VeryCoarseTimer);
        m_scheduledScanTimer.start();
    }
}

void AntivirusController::saveSettings() {
    QSettings settings("BladeAntivirus", "BladeAntivirus");
    settings.setValue("exclusions", m_exclusions);
    settings.setValue("scheduledScanEnabled", m_scheduledScanEnabled);
    settings.setValue("scheduledScanIntervalMinutes", m_scheduledScanIntervalMinutes);
}

void AntivirusController::setRealtimeProtectionEnabled(bool enabled) {
    if (enabled) {
        const QString db = findDatabase();
        const QString cache = dataDir() + "/scan_cache.bin";
        QStringList dirs;
        dirs << QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
        m_realtimeProtection.start(dirs, db, cache);
    } else {
        m_realtimeProtection.stop();
    }
}

