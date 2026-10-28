# BladeAntivirus

**Open-source antivirus project for Windows**

BladeAntivirus is a Windows antivirus project built with C++ and Qt Quick. It aims to provide a modern desktop interface and a modular scanning engine for detecting potentially malicious files.

> **Development status:** Work in progress. Detection capabilities and protection features are actively being developed and tested.

## Features

- **Modern user interface** — dark-themed interface built with Qt Quick and QML.
- **File scanning** — quick and full scan workflows.
- **Detection classification** — designed to distinguish malicious, suspicious, and clean files.
- **PE file analysis** — support for analyzing Windows Portable Executable (PE) files.
- **Scan optimization** — caching and scan-policy components to improve scanning workflows.
- **Threat intelligence updates** — updater components for retrieving threat-related data.
- **Protection settings** — configurable protection and update options.
- **Windows support** — designed for Windows desktop systems.

*Feature availability and detection coverage depend on the current implementation.*

## Technology Stack

- C++20
- Qt 6
- Qt Quick / QML
- CMake
- Ninja / MinGW
- Windows x64

## Requirements

- Windows 10 or later
- Qt 6 with Qt Quick and Qt Quick Controls
- CMake 3.25 or later
- A compatible C++20 compiler
- Ninja or another supported CMake generator

## Build from Source

Clone the repository:

```bash
git clone https://github.com/blade391off/Blade-Antivirus.git
cd Blade-Antivirus
```

Configure the project using your installed Qt kit. For example, with Qt 6 and Ninja on Windows:

```bat
cmake -S . -B out/build/mingw-msys2 -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_PREFIX_PATH=D:/Qt/6.12.0/mingw_64
```

Build the application:

```bat
cmake --build out/build/mingw-msys2 --config Release
```

Adjust the Qt path and compiler configuration to match your environment.

## Security Notice

BladeAntivirus is an experimental security project and should not be relied upon as the sole means of protecting a computer.

- Detection results may include false positives and false negatives.
- A clean result does not guarantee that a file is safe.
- Keep Windows and other security software enabled.
- Test new builds in a controlled environment.
- Do not execute suspicious files just to verify a detection.

## Contributing

Contributions, bug reports, and suggestions are welcome.

When submitting a change:

1. Describe the problem or improvement.
2. Include steps to reproduce bugs when possible.
3. Keep changes focused and test them before opening a pull request.
4. Avoid committing build output, IDE caches, or generated files.

## License

See the repository's `LICENSE` file for the terms under which BladeAntivirus is distributed. Third-party components may be subject to their own licenses; see `LICENSE-THIRD-PARTY.txt`.

## Disclaimer

BladeAntivirus is provided for educational and research purposes. The project is under active development and is supplied without any guarantee of complete detection, reliability, or fitness for a particular purpose.

---

**Repository:** [blade391off/Blade-Antivirus](https://github.com/blade391off/Blade-Antivirus)
