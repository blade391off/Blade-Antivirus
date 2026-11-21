#pragma once

#include <filesystem>

namespace blade::database
{
    // Per-user, writable location the updater writes to:
    //   %LOCALAPPDATA%/BladeAntivirus/BladeAntivirus/database
    std::filesystem::path userDatabaseDir();

    // Location used by builds that did not set an organization name:
    //   %LOCALAPPDATA%/BladeAntivirus/database
    std::filesystem::path legacyDatabaseDir();

    // Copy shipped next to the executable: <exe>/database
    std::filesystem::path bundledDatabaseDir();

    // Development fallback: <source tree>/database (only when defined)
    std::filesystem::path sourceDatabaseDir();

    // Copies hashes.txt from the legacy location when the current one is
    // missing. Returns true when a file was copied.
    bool migrateLegacyDatabase();

    // First usable hashes.txt in the order user -> bundled -> source,
    // or an empty path when none of them exists.
    std::filesystem::path locateHashes();

    // Where updates belong. Creates nothing; the updater creates the folder.
    std::filesystem::path writableHashesPath();
}
