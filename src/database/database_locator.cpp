#include "database_locator.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

#include <system_error>

namespace
{
    std::filesystem::path toPath(const QString& value)
    {
        if (value.isEmpty())
            return {};

        return std::filesystem::path(value.toStdWString());
    }

    QString userDataRoot()
    {
        return QStandardPaths::writableLocation(
            QStandardPaths::AppLocalDataLocation);
    }

    // Only regular non-empty files count: a half-written download or a
    // zero-byte placeholder must not be treated as a usable database.
    bool isUsableDatabase(const std::filesystem::path& path)
    {
        if (path.empty())
            return false;

        std::error_code error;

        return std::filesystem::is_regular_file(path, error)
            && !error
            && std::filesystem::file_size(path, error) > 0
            && !error;
    }
}

namespace blade::database
{
    std::filesystem::path userDatabaseDir()
    {
        const QString root = userDataRoot();

        if (root.isEmpty())
            return {};

        return toPath(root + QStringLiteral("/database"));
    }

    std::filesystem::path legacyDatabaseDir()
    {
        const QString root = userDataRoot();

        if (root.isEmpty())
            return {};

        // <AppLocalDataLocation>/database shifted to
        // <AppLocalDataLocation>/../database once the organization name
        // was introduced, which added one nesting level.
        return toPath(QDir::cleanPath(
            QDir(root).absoluteFilePath(QStringLiteral("../database"))));
    }

    std::filesystem::path bundledDatabaseDir()
    {
        return toPath(
            QCoreApplication::applicationDirPath()
            + QStringLiteral("/database"));
    }

    std::filesystem::path sourceDatabaseDir()
    {
#ifdef BLADE_SOURCE_DIR
        return std::filesystem::path(
            std::u8string(reinterpret_cast<const char8_t*>(BLADE_SOURCE_DIR)))
            / "database";
#else
        return {};
#endif
    }

    bool migrateLegacyDatabase()
    {
        const std::filesystem::path target = writableHashesPath();
        const std::filesystem::path legacy =
            legacyDatabaseDir() / "hashes.txt";

        if (!isUsableDatabase(legacy) || isUsableDatabase(target))
            return false;

        std::error_code error;

        std::filesystem::create_directories(target.parent_path(), error);

        if (error)
            return false;

        if (!std::filesystem::copy_file(
                legacy,
                target,
                std::filesystem::copy_options::overwrite_existing,
                error))
        {
            return false;
        }

        return !error && isUsableDatabase(target);
    }

    std::filesystem::path locateHashes()
    {
        for (const auto& directory :
             { userDatabaseDir(), bundledDatabaseDir(), sourceDatabaseDir() })
        {
            if (directory.empty())
                continue;

            const std::filesystem::path candidate =
                directory / "hashes.txt";

            if (isUsableDatabase(candidate))
                return candidate;
        }

        return {};
    }

    std::filesystem::path writableHashesPath()
    {
        const std::filesystem::path directory = userDatabaseDir();

        if (directory.empty())
            return {};

        return directory / "hashes.txt";
    }
}
