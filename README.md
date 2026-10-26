# BladeAntivirus

**An open-source Windows malware detection project built with C++ and Qt.**

BladeAntivirus is a Windows security project focused on malware detection, file scanning, and a modern desktop interface. The project is developed to explore practical antivirus engineering, signature-based detection, threat intelligence integration, and Windows security.

The source code is publicly available, and development is ongoing.

## Overview

BladeAntivirus combines a native C++ codebase with a Qt Quick interface to provide a desktop environment for malware scanning and protection-related functionality.

The project focuses on:

- File scanning and malware detection.
- Hash-based identification of known threats.
- Threat indicator and signature database updates.
- A modern desktop interface built with Qt Quick and QML.
- Continued development of scanning capabilities and protection features.

Feature availability depends on the current release. See the repository and release notes for the latest implementation status.

## Technology Stack

| Component | Technology |
|---|---|
| Core language | C++ |
| User interface | Qt Quick / QML |
| Build system | CMake |
| Build generator | Ninja |
| Compiler | MinGW-w64 |
| Platform | Windows x64 |

## Download

Prebuilt binaries are available on the GitHub Releases page.

**[Download BladeAntivirus](https://github.com/blade391off/Blade-Antivirus/releases)**

For the latest version, review the release notes and download the asset attached to the corresponding release.

## Installation

1. Open the [Releases page](https://github.com/blade391off/Blade-Antivirus/releases).
2. Select a release.
3. Download the provided Windows executable or other published assets.
4. Run the application on a compatible Windows system.

If the application fails to start, check the release notes and report the issue with relevant error messages.

## Building from Source

The project uses CMake and Qt. To build it from source, you need a compatible C++ compiler, CMake, and a Qt installation that includes the modules required by the project.

Example configuration command for a Qt installation using MinGW and Ninja:

```bash
cmake -S . -B build -G Ninja ^
  -DCMAKE_PREFIX_PATH="D:/Qt/6.12.0/mingw_64"
```

Build the configured project:

```bash
cmake --build build
```

Adjust the Qt path, compiler, generator, and build configuration to match your environment. The commands above are an example configuration, not a guarantee that every checkout will build without additional setup.

## Project Status

BladeAntivirus is under active development. Features, detection coverage, and reliability may change between releases.

Planned improvements may include expanded detection capabilities, improved scanning workflows, and further interface development. Planned features should not be considered available until they are implemented and documented.

## Security Notice

BladeAntivirus is an experimental security project and **is not a replacement for Microsoft Defender or another established security solution**.

Detection results may be incomplete, and false positives or missed detections are possible. Do not rely on BladeAntivirus as your only layer of protection.

Use caution when handling suspicious files. Do not execute unknown samples on a production system.

## Contributing

Contributions, bug reports, and technical feedback are welcome.

Before submitting a change:

1. Review the existing project structure and conventions.
2. Keep changes focused and document relevant behavior.
3. Include clear reproduction steps when reporting a bug.
4. Avoid submitting confidential information, credentials, or live malicious files.

Please use the repository's issue tracker for bug reports and feature requests.

## License

BladeAntivirus is distributed under the **GNU General Public License v3.0 (GPL-3.0)**.

You may use, study, modify, and redistribute the software under the terms of the license. Redistribution and distribution of modified versions must comply with the applicable GPL-3.0 requirements.

See [LICENSE](LICENSE) for the full license text.

---

**Repository:** [blade391off/Blade-Antivirus](https://github.com/blade391off/Blade-Antivirus)
