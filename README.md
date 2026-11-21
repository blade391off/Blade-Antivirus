<img width="256" height="140" alt="image" src="https://github.com/user-attachments/assets/fccee541-3023-4d7a-951d-3798d2824fe8" />

# BladeAntivirus


**An open-source Windows malware detection project built with C++ and Qt.**

BladeAntivirus is a Windows security project focused on malware detection, file
scanning, and a modern desktop interface. It is developed to explore practical
antivirus engineering: signature-based detection, PE analysis, YARA rules,
threat-intelligence updates, and Windows security APIs.

The source code is publicly available and development is ongoing.

## Overview

BladeAntivirus combines a native C++ codebase with a Qt Quick interface to
provide a desktop environment for malware scanning and protection-related
functionality:

- File scanning with SHA-256 hash matching against a threat database.
- YARA rule matching (family, loader, ransomware, stealer and APT rules).
- PE analysis: section entropy, packer detection, entry-point checks, import
  analysis and heuristic scoring.
- Authenticode / catalog signature checks to avoid flagging trusted binaries.
- Scan cache keyed by path, size and modification time.
- Threat database updates over HTTPS with ETag caching.
- System tray integration and optional start with Windows.
- Real-time folder monitoring (see [Limitations](#limitations)).
- Quarantine, exclusions, scan history, process scanner, scheduled scans,
  exportable reports, drag-and-drop and toast notifications.

Feature availability depends on the current release. See the release notes for
the latest implementation status.

## Technology Stack

| Component | Technology |
|---|---|
| Core language | C++20 |
| User interface | Qt Quick / QML |
| Build system | CMake 3.25+ |
| Compiler | MinGW-w64 (13.x) |
| Detection engine | YARA 4.5, Windows CNG (BCrypt) |
| Platform | Windows x64 |

## Download

Prebuilt binaries are available on the GitHub Releases page.

**[Download BladeAntivirus](https://github.com/blade391off/Blade-Antivirus/releases)**

## Installation

1. Open the [Releases page](https://github.com/blade391off/Blade-Antivirus/releases).
2. Download the release archive.
3. Extract it to a folder (the `database` and `yara` folders must stay next to
   the executable).
4. Run `BladeAntivirus.exe`.

The bundled `database/hashes.txt` is used on first start. Press
**Check for updates** to replace it with the full online list.

## Building from Source

Requirements:

- Qt 6.8 or newer (Core, Gui, Qml, Quick, QuickControls2, Widgets, Network)
- CMake 3.25+
- MinGW-w64 with C++20 support
- YARA 4.5 built as a static library
- Static OpenSSL `libcrypto`

YARA and OpenSSL are not vendored. Point the build at your own copies; both are
CMake cache variables, so no source edits are needed:

```bash
cmake -S . -B build -G "MinGW Makefiles" ^
  -DCMAKE_PREFIX_PATH="D:/Qt/6.12.0/mingw_64" ^
  -DYARA_ROOT="D:/yara/install" ^
  -DOPENSSL_CRYPTO="D:/yara/installed/x64-mingw-dynamic-static/lib/libcrypto.a"

cmake --build build -j
```

A preset is available for the reference toolchain:

```bash
cmake --preset mingw-msys2
cmake --build --preset default
```

After every build the `database` and `yara` folders are copied next to the
executable. YARA rules are looked up in this order:

1. `BLADE_YARA_DIR` environment variable
2. `<folder with the executable>/yara`
3. `<source tree>/yara` (development builds)

## Limitations

- **Real-time protection is monitoring, not interception.** Files are scanned
  after they are written to disk using `ReadDirectoryChangesW`. Blocking a file
  before it is executed requires a kernel minifilter driver, which this project
  does not implement. Do not rely on it as an on-access scanner.
- Hash matching only detects known samples; heuristics and YARA cover the rest
  with a higher false-positive rate.
- The bundled database is a small starter set. Run an update to get the full
  list.
- **Detection levels.** A hash-database hit is reported as *malicious*. A YARA
  match on its own is reported as *suspicious* unless the PE heuristics also
  flag the file, so a single over-broad rule cannot condemn a clean program.
  Signed files matching only YARA rules are additionally marked as a possible
  false positive.
- **Rules that cannot be compiled are skipped, not fatal.** YARA refuses to
  accept more files after an error, so the engine retries the ruleset with the
  offending file blocked and keeps everything else. Rules that need modules this
  libyara build lacks (`macho`, `dotnet`, `elf`) or that redefine an existing
  rule identifier are logged and skipped. The bundled rules require the `pe`,
  `hash` and `math` modules.
- YARA compilation happens on every engine start (about two seconds for the
  bundled ruleset).

## Security Notice

BladeAntivirus is an experimental security project and **is not a replacement
for Microsoft Defender or another established security solution**. Detection
results may be incomplete, and false positives or missed detections are
possible. Do not rely on BladeAntivirus as your only layer of protection.

Use caution when handling suspicious files. Do not execute unknown samples on a
production system.

## Contributing

Contributions, bug reports, and technical feedback are welcome.

Before submitting a change:

1. Review the existing project structure and conventions.
2. Keep changes focused and document relevant behavior.
3. Include clear reproduction steps when reporting a bug.
4. Avoid submitting confidential information, credentials, or live malicious
   files.

Please use the repository's issue tracker for bug reports and feature requests.

## License

BladeAntivirus is distributed under the **GNU General Public License v3.0
(GPL-3.0)**. You may use, study, modify, and redistribute the software under the
terms of the license. Redistribution and distribution of modified versions must
comply with the applicable GPL-3.0 requirements.

See [LICENSE](LICENSE) for the full license text.

---

**Repository:** [blade391off/Blade-Antivirus](https://github.com/blade391off/Blade-Antivirus)
