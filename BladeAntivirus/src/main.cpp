#include <windows.h>
#include <commdlg.h>
#include <windowsx.h>

#include <string>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>

#include "scanner/scanner.h"
#include "signs/signs.hpp"
#include "updater/updater.h"

#pragma comment(lib, "comdlg32.lib")

namespace
{
    constexpr wchar_t WINDOW_CLASS[] = L"BladeAntivirusMainWindow";
    constexpr wchar_t BUTTON_CLASS[] = L"BladeAntivirusButton";
    constexpr wchar_t PANEL_CLASS[] = L"BladeAntivirusPanel";

    constexpr int ID_NAV_DASHBOARD = 1001;
    constexpr int ID_NAV_SCANNER = 1002;
    constexpr int ID_NAV_UPDATES = 1003;
    constexpr int ID_NAV_ABOUT = 1004;

    constexpr int ID_SCAN_NOW = 1010;
    constexpr int ID_SELECT_FILE = 1011;
    constexpr int ID_SCAN_FILE = 1012;
    constexpr int ID_CHECK_UPDATE = 1013;

    constexpr UINT WM_BLADE_ACTIVE = WM_USER + 10;

    constexpr int SIDEBAR_WIDTH = 245;
    constexpr int FOOTER_HEIGHT = 34;

    // Color definitions
#define COLOR_BACKGROUND RGB(11, 12, 15)
#define COLOR_SIDEBAR RGB(15, 16, 20)
#define COLOR_PANEL RGB(21, 23, 28)
#define COLOR_PANEL_ALT RGB(26, 28, 34)
#define COLOR_BUTTON RGB(28, 30, 37)
#define COLOR_BUTTON_HOV RGB(37, 40, 49)
#define COLOR_BORDER RGB(45, 48, 57)

#define COLOR_TEXT RGB(245, 247, 250)
#define COLOR_MUTED RGB(155, 161, 172)
#define COLOR_DIM RGB(105, 111, 123)

#define COLOR_ACCENT RGB(48, 125, 255)
#define COLOR_ACCENT_HOV RGB(67, 141, 255)

#define COLOR_GREEN RGB(56, 201, 117)
#define COLOR_RED RGB(230, 79, 79)
#define COLOR_YELLOW RGB(238, 184, 72)

    HINSTANCE g_instance = nullptr;

    HWND g_mainWindow = nullptr;
    HWND g_sidebar = nullptr;
    HWND g_content = nullptr;
    HWND g_footer = nullptr;

    HWND g_navDashboard = nullptr;
    HWND g_navScanner = nullptr;
    HWND g_navUpdates = nullptr;
    HWND g_navAbout = nullptr;

    HWND g_filePath = nullptr;
    HWND g_result = nullptr;
    HWND g_scanStatus = nullptr;
    HWND g_updateStatus = nullptr;

    std::wstring g_currentFile;

    HFONT g_font = nullptr;
    HFONT g_fontSmall = nullptr;
    HFONT g_fontMedium = nullptr;
    HFONT g_fontBold = nullptr;
    HFONT g_fontTitle = nullptr;
    HFONT g_fontBig = nullptr;
    HFONT g_fontHuge = nullptr;
    HFONT g_fontMono = nullptr;

    HBRUSH g_backgroundBrush = nullptr;
    HBRUSH g_sidebarBrush = nullptr;
    HBRUSH g_panelBrush = nullptr;
    HBRUSH g_panelAltBrush = nullptr;
    HBRUSH g_editBrush = nullptr;

    enum class Page
    {
        Dashboard,
        Scanner,
        Updates,
        About
    };

    Page g_currentPage = Page::Dashboard;

    struct ButtonState
    {
        bool hover = false;
        bool pressed = false;
        bool active = false;
        bool tracking = false;
        HFONT font = nullptr;
    };

    std::wstring ToWide(const std::string& value)
    {
        if (value.empty())
            return L"";

        int size = MultiByteToWideChar(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            nullptr,
            0
        );

        if (size <= 0)
            return L"";

        std::wstring result(size, L'\0');

        MultiByteToWideChar(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            result.data(),
            size
        );

        return result;
    }

    std::string ToNarrow(const std::wstring& value)
    {
        if (value.empty())
            return "";

        int size = WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            nullptr,
            0,
            nullptr,
            nullptr
        );

        if (size <= 0)
            return "";

        std::string result(size, '\0');

        WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            result.data(),
            size,
            nullptr,
            nullptr
        );

        return result;
    }

    void SetText(HWND hwnd, const std::wstring& text)
    {
        if (hwnd)
            SetWindowTextW(hwnd, text.c_str());
    }

    void SetLabelColor(HWND hwnd, COLORREF color)
    {
        if (!hwnd)
            return;

        SetPropW(
            hwnd,
            L"BladeTextColor",
            reinterpret_cast<HANDLE>(
                static_cast<ULONG_PTR>(color)
                )
        );

        InvalidateRect(hwnd, nullptr, TRUE);
    }

    HFONT CreateBladeFont(
        int height,
        int weight = FW_NORMAL,
        const wchar_t* face = L"Segoe UI"
    )
    {
        return CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            FALSE,
            FALSE,
            FALSE,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            face
        );
    }

    HWND CreateLabel(
        HWND parent,
        const std::wstring& text,
        int x,
        int y,
        int width,
        int height,
        HFONT font = nullptr,
        COLORREF color = COLOR_TEXT
    )
    {
        HWND hwnd = CreateWindowExW(
            0,
            L"STATIC",
            text.c_str(),
            WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
            x,
            y,
            width,
            height,
            parent,
            nullptr,
            g_instance,
            nullptr
        );

        if (hwnd)
        {
            SendMessageW(
                hwnd,
                WM_SETFONT,
                reinterpret_cast<WPARAM>(font ? font : g_font),
                TRUE
            );

            SetLabelColor(hwnd, color);
        }

        return hwnd;
    }

    HWND CreateBladePanel(
        HWND parent,
        int x,
        int y,
        int width,
        int height,
        COLORREF background
    )
    {
        return CreateWindowExW(
            0,
            PANEL_CLASS,
            L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
            x,
            y,
            width,
            height,
            parent,
            nullptr,
            g_instance,
            reinterpret_cast<LPVOID>(&background)
        );
    }

    HWND CreateBladeButton(
        HWND parent,
        int id,
        const std::wstring& text,
        int x,
        int y,
        int width,
        int height,
        bool active = false
    )
    {
        HWND hwnd = CreateWindowExW(
            0,
            BUTTON_CLASS,
            text.c_str(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            x,
            y,
            width,
            height,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            g_instance,
            nullptr
        );

        if (hwnd)
        {
            SendMessageW(
                hwnd,
                WM_SETFONT,
                reinterpret_cast<WPARAM>(g_fontMedium),
                TRUE
            );

            SendMessageW(
                hwnd,
                WM_BLADE_ACTIVE,
                active ? 1 : 0,
                0
            );
        }

        return hwnd;
    }

    void DestroyContentChildren()
    {
        if (!g_content)
            return;

        HWND child = GetWindow(g_content, GW_CHILD);

        while (child)
        {
            HWND next = GetWindow(child, GW_HWNDNEXT);
            DestroyWindow(child);
            child = next;
        }

        g_filePath = nullptr;
        g_result = nullptr;
        g_scanStatus = nullptr;
        g_updateStatus = nullptr;
    }

    void SetActiveNavigation(Page page)
    {
        g_currentPage = page;

        SendMessageW(
            g_navDashboard,
            WM_BLADE_ACTIVE,
            page == Page::Dashboard,
            0
        );

        SendMessageW(
            g_navScanner,
            WM_BLADE_ACTIVE,
            page == Page::Scanner,
            0
        );

        SendMessageW(
            g_navUpdates,
            WM_BLADE_ACTIVE,
            page == Page::Updates,
            0
        );

        SendMessageW(
            g_navAbout,
            WM_BLADE_ACTIVE,
            page == Page::About,
            0
        );
    }

    void ShowDashboard();
    void ShowScanner();
    void ShowUpdates();
    void ShowAbout();

    void Navigate(Page page)
    {
        switch (page)
        {
        case Page::Dashboard:
            ShowDashboard();
            break;

        case Page::Scanner:
            ShowScanner();
            break;

        case Page::Updates:
            ShowUpdates();
            break;

        case Page::About:
            ShowAbout();
            break;
        }

        SetActiveNavigation(page);
    }

    std::wstring GetExecutableDirectory()
    {
        wchar_t buffer[MAX_PATH]{};

        DWORD length = GetModuleFileNameW(
            nullptr,
            buffer,
            MAX_PATH
        );

        if (length == 0)
            return L".";

        std::filesystem::path path(buffer);

        return path.parent_path().wstring();
    }

    std::string ResolveDatabasePath()
    {
        std::filesystem::path exeDir(GetExecutableDirectory());

        std::filesystem::path candidates[] =
        {
            exeDir / L"database" / L"hashes.txt",
            exeDir / L"..\\..\\..\\database\\hashes.txt",
            std::filesystem::current_path() / L"database" / L"hashes.txt"
        };

        for (const auto& candidate : candidates)
        {
            std::error_code ec;

            if (std::filesystem::exists(candidate, ec))
            {
                return ToNarrow(
                    std::filesystem::weakly_canonical(candidate, ec).wstring()
                );
            }
        }

        return ToNarrow(
            (std::filesystem::current_path() /
                L"database" /
                L"hashes.txt").wstring()
        );
    }

    std::string ResolveVersionPath()
    {
        std::filesystem::path exeDir(GetExecutableDirectory());

        std::filesystem::path candidates[] =
        {
            exeDir / L"database" / L"version.txt",
            exeDir / L"..\\..\\..\\database\\version.txt",
            std::filesystem::current_path() / L"database" / L"version.txt"
        };

        for (const auto& candidate : candidates)
        {
            std::error_code ec;

            if (std::filesystem::exists(candidate, ec))
            {
                return ToNarrow(
                    std::filesystem::weakly_canonical(candidate, ec).wstring()
                );
            }
        }

        return ToNarrow(
            (std::filesystem::current_path() /
                L"database" /
                L"version.txt").wstring()
        );
    }

    void SelectFile()
    {
        if (!g_filePath)
            return;

        OPENFILENAMEW ofn{};
        wchar_t fileName[MAX_PATH]{};

        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_mainWindow;
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;

        ofn.lpstrFilter =
            L"Executable files (*.exe;*.dll)\0*.exe;*.dll\0"
            L"All files (*.*)\0*.*\0";

        ofn.nFilterIndex = 1;
        ofn.Flags =
            OFN_PATHMUSTEXIST |
            OFN_FILEMUSTEXIST |
            OFN_NOCHANGEDIR;

        if (GetOpenFileNameW(&ofn))
        {
            g_currentFile = fileName;
            SetText(g_filePath, g_currentFile);

            if (g_scanStatus)
            {
                SetText(
                    g_scanStatus,
                    L"Ready to scan"
                );

                SetLabelColor(
                    g_scanStatus,
                    COLOR_MUTED
                );
            }

            if (g_result)
            {
                SetText(
                    g_result,
                    L"Select a file and press SCAN FILE."
                );
            }
        }
    }

    std::wstring BuildScanResult(
        const ScanResult& scan,
        const SignsResult& signs
    )
    {
        std::wstringstream output;

        output
            << L"BLADEANTIVIRUS SCAN RESULT\n"
            << L"========================================\n\n";

        output
            << L"File:\n"
            << g_currentFile
            << L"\n\n";

        output
            << L"HASH ENGINE\n"
            << L"----------------------------------------\n";

        output
            << L"Hash match: "
            << (scan.hashMatch ? L"MATCH" : L"NO MATCH")
            << L"\n";

        output
            << L"PE file: "
            << (scan.isPE ? L"YES" : L"NO")
            << L"\n";

        if (!scan.verdict.empty())
        {
            output
                << L"Engine verdict: "
                << ToWide(scan.verdict)
                << L"\n";
        }

        output
            << L"\nSTATIC SIGNS\n"
            << L"----------------------------------------\n";

        output
            << L"Score: "
            << signs.score
            << L"\n";

        output << L"Matches:\n";

        if (signs.matches.empty())
        {
            output << L"None\n";
        }
        else
        {
            for (const auto& m : signs.matches)
            {
                output
                    << L"- "
                    << ToWide(m.name)
                    << L"  (+" << m.score << L")\n"
                    << ToWide(m.description)
                    << L"\n";
            }
        }

        output
            << L"\nFINAL VERDICT\n"
            << L"----------------------------------------\n";

        if (scan.hashMatch ||
            signs.verdict == "MALICIOUS" ||
            signs.verdict == "SUSPICIOUS")
        {
            output
                << L"THREAT DETECTED\n"
                << L"\nBladeAntivirus detected a suspicious indicator.";
        }
        else
        {
            output
                << L"NO THREATS DETECTED\n"
                << L"\nNo matching indicators were found.";
        }

        return output.str();
    }

    void ScanCurrentFile()
    {
        if (!g_filePath || !g_result || !g_scanStatus)
            return;

        if (g_currentFile.empty())
        {
            SetText(
                g_scanStatus,
                L"Please select a file first."
            );

            SetLabelColor(
                g_scanStatus,
                COLOR_YELLOW
            );

            return;
        }

        SetText(
            g_scanStatus,
            L"Scanning file..."
        );

        SetLabelColor(
            g_scanStatus,
            COLOR_ACCENT
        );

        SetText(
            g_result,
            L"BladeAntivirus is analyzing the selected file..."
        );

        UpdateWindow(g_mainWindow);

        std::string filePath = ToNarrow(g_currentFile);
        std::string databasePath = ResolveDatabasePath();

        Scanner scanner;

        bool initialized = scanner.initialize(databasePath);

        if (!initialized)
        {
            SetText(
                g_scanStatus,
                L"Scanner initialization failed."
            );

            SetLabelColor(
                g_scanStatus,
                COLOR_RED
            );

            SetText(
                g_result,
                L"Could not initialize the hash scanner.\n\n"
                L"Database path:\n" +
                ToWide(databasePath)
            );

            return;
        }

        ScanResult scanResult =
            scanner.scan(filePath);

        SignsEngine signsEngine;

        SignsResult signsResult =
            signsEngine.analyze(filePath);

        bool detected =
            scanResult.hashMatch ||
            signsResult.verdict == "MALICIOUS" ||
            signsResult.verdict == "SUSPICIOUS";

        SetText(
            g_scanStatus,
            detected
            ? L"Threat detected"
            : L"Scan completed"
        );

        SetLabelColor(
            g_scanStatus,
            detected
            ? COLOR_RED
            : COLOR_GREEN
        );

        SetText(
            g_result,
            BuildScanResult(
                scanResult,
                signsResult
            )
        );
    }

    void CheckUpdates()
    {
        if (!g_updateStatus)
            return;

        SetText(
            g_updateStatus,
            L"Checking for database updates..."
        );

        SetLabelColor(
            g_updateStatus,
            COLOR_ACCENT
        );

        UpdateWindow(g_mainWindow);

        const std::string manifestUrl =
            "https://YOUR-DOMAIN.example/updates/manifest.txt";

        if (manifestUrl.find("YOUR-DOMAIN") != std::string::npos)
        {
            SetText(
                g_updateStatus,
                L"Update server is not configured yet."
            );

            SetLabelColor(
                g_updateStatus,
                COLOR_YELLOW
            );

            return;
        }

        Updater updater;

        std::string status;

        bool success =
            updater.updateDatabase(
                manifestUrl,
                ResolveDatabasePath(),
                ResolveVersionPath(),
                status
            );

        SetText(
            g_updateStatus,
            ToWide(status)
        );

        SetLabelColor(
            g_updateStatus,
            success
            ? COLOR_GREEN
            : COLOR_RED
        );
    }

    void ShowDashboard()
    {
        DestroyContentChildren();

        SetActiveNavigation(Page::Dashboard);

        RECT rc{};
        GetClientRect(g_content, &rc);

        int width = rc.right;

        CreateLabel(
            g_content,
            L"Dashboard",
            42,
            36,
            width - 84,
            48,
            g_fontTitle
        );

        CreateLabel(
            g_content,
            L"Security overview and protection status",
            44,
            82,
            width - 88,
            28,
            g_font,
            COLOR_MUTED
        );

        HWND protectionCard =
            CreateBladePanel(
                g_content,
                42,
                132,
                width - 84,
                175,
                COLOR_PANEL
            );

        // small green indicator panel instead of a glyph
        CreateBladePanel(
            protectionCard,
            30,
            32,
            50,
            50,
            COLOR_GREEN
        );

        CreateLabel(
            protectionCard,
            L"Protection Status",
            90,
            28,
            500,
            45,
            g_fontBig,
            COLOR_TEXT
        );

        CreateLabel(
            protectionCard,
            L"BladeAntivirus protection systems are ready.",
            92,
            78,
            620,
            30,
            g_font,
            COLOR_MUTED
        );

        CreateLabel(
            protectionCard,
            L"SHA-256 - Static signs - PE analysis",
            92,
            110,
            700,
            25,
            g_fontSmall,
            COLOR_DIM
        );

        CreateBladeButton(
            protectionCard,
            ID_SCAN_NOW,
            L"Scan Now",
            width - 300,
            61,
            220,
            55,
            true
        );

        int cardGap = 18;
        int cardsY = 335;
        int cardsWidth = width - 84;
        int cardWidth =
            (cardsWidth - cardGap * 2) / 3;

        HWND card1 =
            CreateBladePanel(
                g_content,
                42,
                cardsY,
                cardWidth,
                140,
                COLOR_PANEL
            );

        CreateLabel(
            card1,
            L"Threat Database",
            22,
            20,
            cardWidth - 44,
            24,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            card1,
            L"ACTIVE",
            22,
            55,
            cardWidth - 44,
            40,
            g_fontBig,
            COLOR_GREEN
        );

        CreateLabel(
            card1,
            L"SHA-256 indicators",
            22,
            105,
            cardWidth - 44,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        HWND card2 =
            CreateBladePanel(
                g_content,
                42 + cardWidth + cardGap,
                cardsY,
                cardWidth,
                140,
                COLOR_PANEL
            );

        CreateLabel(
            card2,
            L"Static Analysis",
            22,
            20,
            cardWidth - 44,
            24,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            card2,
            L"READY",
            22,
            55,
            cardWidth - 44,
            40,
            g_fontBig,
            COLOR_GREEN
        );

        CreateLabel(
            card2,
            L"PE file inspection",
            22,
            105,
            cardWidth - 44,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        HWND card3 =
            CreateBladePanel(
                g_content,
                42 + (cardWidth + cardGap) * 2,
                cardsY,
                cardWidth,
                140,
                COLOR_PANEL
            );

        CreateLabel(
            card3,
            L"Sign Engine",
            22,
            20,
            cardWidth - 44,
            24,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            card3,
            L"READY",
            22,
            55,
            cardWidth - 44,
            40,
            g_fontBig,
            COLOR_GREEN
        );

        CreateLabel(
            card3,
            L"Static indicators",
            22,
            105,
            cardWidth - 44,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        CreateLabel(
            g_content,
            L"Quick Scan",
            42,
            505,
            400,
            30,
            g_fontMedium
        );

        CreateLabel(
            g_content,
            L"Run a local scan to inspect a suspicious file.",
            42,
            540,
            width - 84,
            25,
            g_fontSmall,
            COLOR_MUTED
        );
    }

    void ShowScanner()
    {
        DestroyContentChildren();

        SetActiveNavigation(Page::Scanner);

        RECT rc{};
        GetClientRect(g_content, &rc);

        int width = rc.right;

        CreateLabel(
            g_content,
            L"Scanner",
            42,
            36,
            width - 84,
            48,
            g_fontTitle
        );
        // no-op patch: ensure context consistency

        CreateLabel(
            g_content,
            L"Analyze a file using BladeAntivirus detection engines",
            44,
            82,
            width - 88,
            28,
            g_font,
            COLOR_MUTED
        );

        HWND targetCard =
            CreateBladePanel(
                g_content,
                42,
                132,
                width - 84,
                150,
                COLOR_PANEL
            );

        CreateLabel(
            targetCard,
            L"TARGET FILE",
            24,
            22,
            250,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        g_filePath =
            CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                g_currentFile.empty()
                ? L"No file selected"
                : g_currentFile.c_str(),
                WS_CHILD |
                WS_VISIBLE |
                ES_AUTOHSCROLL |
                ES_LEFT,
                24,
                60,
                width - 350,
                42,
                targetCard,
                nullptr,
                g_instance,
                nullptr
            );

        SendMessageW(
            g_filePath,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(g_font),
            TRUE
        );

        CreateBladeButton(
            targetCard,
            ID_SELECT_FILE,
            L"SELECT FILE",
            width - 300,
            60,
            250,
            42,
            false
        );
        CreateBladeButton(
            g_content,
            ID_SCAN_FILE,
            L"Scan file",
            42,
            310,
            230,
            55,
            true
        );

        g_scanStatus =
            CreateLabel(
                g_content,
                L"Ready to scan",
                300,
                323,
                width - 342,
                30,
                g_fontMedium,
                COLOR_MUTED
            );

        HWND resultCard =
            CreateBladePanel(
                g_content,
                42,
                390,
                width - 84,
                245,
                COLOR_PANEL
            );

        CreateLabel(
            resultCard,
            L"Scan result",
            24,
            20,
            300,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        g_result =
            CreateWindowExW(
                WS_EX_CLIENTEDGE,
                L"EDIT",
                L"Select a file and press SCAN FILE.",
                WS_CHILD |
                WS_VISIBLE |
                WS_VSCROLL |
                ES_MULTILINE |
                ES_AUTOVSCROLL |
                ES_READONLY |
                ES_LEFT,
                24,
                58,
                width - 132,
                165,
                resultCard,
                nullptr,
                g_instance,
                nullptr
            );

        SendMessageW(
            g_result,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(g_fontMono),
            TRUE
        );
    }

    void ShowUpdates()
    {
        DestroyContentChildren();

        SetActiveNavigation(Page::Updates);

        RECT rc{};
        GetClientRect(g_content, &rc);

        int width = rc.right;

        CreateLabel(
            g_content,
            L"Updates",
            42,
            36,
            width - 84,
            48,
            g_fontTitle
        );

        CreateLabel(
            g_content,
            L"Keep the local threat database up to date",
            44,
            82,
            width - 88,
            28,
            g_font,
            COLOR_MUTED
        );

        HWND updateCard =
            CreateBladePanel(
                g_content,
                42,
                132,
                width - 84,
                225,
                COLOR_PANEL
            );

        CreateLabel(
            updateCard,
            L"THREAT DATABASE",
            28,
            25,
            300,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            updateCard,
            L"SHA-256 DATABASE",
            28,
            65,
            450,
            40,
            g_fontBig
        );

        CreateLabel(
            updateCard,
            L"Local indicator database",
            28,
            112,
            450,
            25,
            g_fontSmall,
            COLOR_DIM
        );

        CreateBladeButton(
            updateCard,
            ID_CHECK_UPDATE,
            L"CHECK FOR UPDATES",
            width - 340,
            72,
            285,
            55,
            true
        );

        g_updateStatus =
            CreateLabel(
                updateCard,
                L"Ready to check for updates",
                28,
                165,
                width - 80,
                28,
                g_fontSmall,
                COLOR_MUTED
            );

        HWND infoCard =
            CreateBladePanel(
                g_content,
                42,
                385,
                width - 84,
                155,
                COLOR_PANEL
            );

        CreateLabel(
            infoCard,
            L"UPDATE INFORMATION",
            24,
            22,
            350,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            infoCard,
            L"Database updates are downloaded through the configured updater.",
            24,
            60,
            width - 130,
            25,
            g_font,
            COLOR_TEXT
        );

        CreateLabel(
            infoCard,
            L"Manifest URL can be configured in the updater settings.",
            24,
            96,
            width - 130,
            25,
            g_fontSmall,
            COLOR_DIM
        );
    }

    void ShowAbout()
    {
        DestroyContentChildren();

        SetActiveNavigation(Page::About);

        RECT rc{};
        GetClientRect(g_content, &rc);

        int width = rc.right;

        CreateLabel(
            g_content,
            L"About BladeAntivirus",
            42,
            36,
            width - 84,
            48,
            g_fontTitle
        );

        CreateLabel(
            g_content,
            L"Lightweight Windows malware analysis and detection engine",
            44,
            82,
            width - 88,
            28,
            g_font,
            COLOR_MUTED
        );

        HWND aboutCard =
            CreateBladePanel(
                g_content,
                42,
                132,
                width - 84,
                190,
                COLOR_PANEL
            );

        CreateLabel(
            aboutCard,
            L"BLADE",
            28,
            24,
            400,
            45,
            g_fontHuge,
            COLOR_ACCENT
        );

        CreateLabel(
            aboutCard,
            L"BladeAntivirus",
            28,
            76,
            500,
            42,
            g_fontBig
        );

        CreateLabel(
            aboutCard,
            L"Native C++ security application for Windows",
            28,
            124,
            650,
            25,
            g_font,
            COLOR_MUTED
        );

        CreateLabel(
            aboutCard,
            L"Version 1.0.0",
            width - 250,
            28,
            180,
            30,
            g_fontSmall,
            COLOR_MUTED
        );

        int gap = 18;
        int cardWidth = (width - 84 - gap) / 2;

        HWND engine1 =
            CreateBladePanel(
                g_content,
                42,
                345,
                cardWidth,
                130,
                COLOR_PANEL
            );

        CreateLabel(
            engine1,
            L"SHA-256 ENGINE",
            22,
            20,
            cardWidth - 44,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            engine1,
            L"Hash Detection",
            22,
            55,
            cardWidth - 44,
            32,
            g_fontMedium
        );

        CreateLabel(
            engine1,
            L"Local indicator database",
            22,
            94,
            cardWidth - 44,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        HWND engine2 =
            CreateBladePanel(
                g_content,
                42 + cardWidth + gap,
                345,
                cardWidth,
                130,
                COLOR_PANEL
            );

        CreateLabel(
            engine2,
            L"STATIC SIGNS",
            22,
            20,
            cardWidth - 44,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            engine2,
            L"Static Analysis",
            22,
            55,
            cardWidth - 44,
            32,
            g_fontMedium
        );

        CreateLabel(
            engine2,
            L"Local file indicators",
            22,
            94,
            cardWidth - 44,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        HWND engine3 =
            CreateBladePanel(
                g_content,
                42,
                493,
                cardWidth,
                130,
                COLOR_PANEL
            );

        CreateLabel(
            engine3,
            L"PE ANALYZER",
            22,
            20,
            cardWidth - 44,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            engine3,
            L"Portable Executable",
            22,
            55,
            cardWidth - 44,
            32,
            g_fontMedium
        );

        CreateLabel(
            engine3,
            L"Windows PE inspection",
            22,
            94,
            cardWidth - 44,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        HWND engine4 =
            CreateBladePanel(
                g_content,
                42 + cardWidth + gap,
                493,
                cardWidth,
                130,
                COLOR_PANEL
            );

        CreateLabel(
            engine4,
            L"UPDATER",
            22,
            20,
            cardWidth - 44,
            25,
            g_fontSmall,
            COLOR_MUTED
        );

        CreateLabel(
            engine4,
            L"Database Updates",
            22,
            55,
            cardWidth - 44,
            32,
            g_fontMedium
        );

        CreateLabel(
            engine4,
            L"WinHTTP update engine",
            22,
            94,
            cardWidth - 44,
            22,
            g_fontSmall,
            COLOR_DIM
        );
    }

    void CreateSidebar()
    {
        CreateLabel(
            g_sidebar,
            L"BLADE",
            28,
            28,
            190,
            48,
            g_fontHuge,
            COLOR_TEXT
        );

        CreateLabel(
            g_sidebar,
            L"ANTIVIRUS",
            31,
            76,
            180,
            22,
            g_fontSmall,
            COLOR_ACCENT
        );

        HWND line =
            CreateWindowExW(
                0,
                L"STATIC",
                L"",
                WS_CHILD | WS_VISIBLE,
                28,
                116,
                185,
                1,
                g_sidebar,
                nullptr,
                g_instance,
                nullptr
            );

        SendMessageW(
            line,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(g_font),
            TRUE
        );

        g_navDashboard =
            CreateBladeButton(
                g_sidebar,
                ID_NAV_DASHBOARD,
                L"Dashboard",
                20,
                145,
                205,
                46,
                true
            );

        // Ensure nav button text is set and visible
        if (g_navDashboard)
            SetWindowTextW(g_navDashboard, L"Dashboard");

        g_navScanner =
            CreateBladeButton(
                g_sidebar,
                ID_NAV_SCANNER,
                L"Scanner",
                20,
                198,
                205,
                46
            );

        if (g_navScanner)
            SetWindowTextW(g_navScanner, L"Scanner");

        g_navUpdates =
            CreateBladeButton(
                g_sidebar,
                ID_NAV_UPDATES,
                L"Updates",
                20,
                251,
                205,
                46
            );

        if (g_navUpdates)
            SetWindowTextW(g_navUpdates, L"Updates");

        g_navAbout =
            CreateBladeButton(
                g_sidebar,
                ID_NAV_ABOUT,
                L"About",
                20,
                304,
                205,
                46
            );

        if (g_navAbout)
            SetWindowTextW(g_navAbout, L"About");

        CreateLabel(
            g_sidebar,
            L"PROTECTION",
            28,
            530,
            180,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        CreateLabel(
            g_sidebar,
            L"Protection: Active",
            28,
            560,
            180,
            28,
            g_fontMedium,
            COLOR_GREEN
        );

        CreateLabel(
            g_sidebar,
            L"Local protection engine",
            28,
            592,
            190,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        CreateLabel(
            g_sidebar,
            L"BladeAntivirus",
            28,
            650,
            190,
            22,
            g_fontSmall,
            COLOR_DIM
        );

        CreateLabel(
            g_sidebar,
            L"Windows Security Tool",
            28,
            676,
            190,
            22,
            g_fontSmall,
            COLOR_DIM
        );
    }

    void LayoutMainWindow()
    {
        if (!g_mainWindow)
            return;

        RECT rc{};
        GetClientRect(g_mainWindow, &rc);

        int width = rc.right;
        int height = rc.bottom;

        int contentHeight =
            height - FOOTER_HEIGHT;

        if (g_sidebar)
        {
            MoveWindow(
                g_sidebar,
                0,
                0,
                SIDEBAR_WIDTH,
                contentHeight,
                TRUE
            );
        }

        if (g_content)
        {
            MoveWindow(
                g_content,
                SIDEBAR_WIDTH,
                0,
                width - SIDEBAR_WIDTH,
                contentHeight,
                TRUE
            );
        }

        if (g_footer)
        {
            MoveWindow(
                g_footer,
                SIDEBAR_WIDTH,
                contentHeight,
                width - SIDEBAR_WIDTH,
                FOOTER_HEIGHT,
                TRUE
            );
        }

        if (g_currentPage == Page::Scanner)
        {
            RECT contentRc{};
            GetClientRect(g_content, &contentRc);

            int contentWidth = contentRc.right;

            if (g_filePath)
            {
                MoveWindow(
                    g_filePath,
                    24,
                    60,
                    contentWidth - 350,
                    42,
                    TRUE
                );
            }

            if (g_result)
            {
                HWND resultCard = GetParent(g_result);

                RECT resultRc{};
                GetClientRect(resultCard, &resultRc);

                MoveWindow(
                    g_result,
                    24,
                    58,
                    resultRc.right - 48,
                    resultRc.bottom - 80,
                    TRUE
                );
            }
        }

        InvalidateRect(g_mainWindow, nullptr, TRUE);
    }

    LRESULT CALLBACK BladeButtonProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam
    )
    {
        ButtonState* state =
            reinterpret_cast<ButtonState*>(
                GetWindowLongPtrW(
                    hwnd,
                    GWLP_USERDATA
                )
                );

        switch (message)
        {
        case WM_NCCREATE:
        {
            auto* newState = new ButtonState();

            SetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA,
                reinterpret_cast<LONG_PTR>(newState)
            );

            return TRUE;
        }

        case WM_SETFONT:
            if (state)
            {
                state->font =
                    reinterpret_cast<HFONT>(wParam);

                InvalidateRect(
                    hwnd,
                    nullptr,
                    TRUE
                );
            }

            return 0;

        case WM_BLADE_ACTIVE:
            if (state)
            {
                state->active =
                    (wParam != 0);

                InvalidateRect(
                    hwnd,
                    nullptr,
                    TRUE
                );
            }

            return 0;

        case WM_MOUSEMOVE:
            if (state)
            {
                if (!state->tracking)
                {
                    TRACKMOUSEEVENT tme{};
                    tme.cbSize =
                        sizeof(TRACKMOUSEEVENT);
                    tme.dwFlags = TME_LEAVE;
                    tme.hwndTrack = hwnd;

                    TrackMouseEvent(&tme);

                    state->tracking = true;
                }

                if (!state->hover)
                {
                    state->hover = true;

                    InvalidateRect(
                        hwnd,
                        nullptr,
                        TRUE
                    );
                }
            }

            break;

        case WM_MOUSELEAVE:
            if (state)
            {
                state->hover = false;
                state->tracking = false;

                InvalidateRect(
                    hwnd,
                    nullptr,
                    TRUE
                );
            }

            break;

        case WM_LBUTTONDOWN:
            if (state)
            {
                state->pressed = true;

                SetCapture(hwnd);

                InvalidateRect(
                    hwnd,
                    nullptr,
                    TRUE
                );
            }

            return 0;

        case WM_LBUTTONUP:
            if (state)
            {
                bool wasPressed =
                    state->pressed;

                state->pressed = false;

                if (GetCapture() == hwnd)
                    ReleaseCapture();

                RECT rc{};
                GetClientRect(hwnd, &rc);

                POINT pt{};
                pt.x = GET_X_LPARAM(lParam);
                pt.y = GET_Y_LPARAM(lParam);

                bool inside =
                    PtInRect(&rc, pt) != FALSE;

                InvalidateRect(
                    hwnd,
                    nullptr,
                    TRUE
                );

                if (wasPressed && inside)
                {
                {
                    HWND target = GetAncestor(hwnd, GA_ROOT);
                    if (!target)
                        target = GetParent(hwnd);

                    SendMessageW(
                        target,
                        WM_COMMAND,
                        MAKEWPARAM(
                            GetDlgCtrlID(hwnd),
                            BN_CLICKED
                        ),
                        reinterpret_cast<LPARAM>(hwnd)
                    );
                }
                    // Briefly show pressed animation
                    state->pressed = true;
                    InvalidateRect(hwnd, nullptr, TRUE);
                    SetTimer(hwnd, 1, 120, nullptr);
                }
            }

            return 0;

        case WM_KEYDOWN:
            if (wParam == VK_SPACE ||
                wParam == VK_RETURN)
            {
                if (state)
                {
                    state->pressed = true;

                    InvalidateRect(
                        hwnd,
                        nullptr,
                        TRUE
                    );
                }

                return 0;
            }

            break;

        case WM_KEYUP:
            if (wParam == VK_SPACE ||
                wParam == VK_RETURN)
            {
                if (state)
                {
                    // show pressed briefly when activated by keyboard
                    state->pressed = true;
                    InvalidateRect(hwnd, nullptr, TRUE);
                    SetTimer(hwnd, 1, 120, nullptr);
                }

                {
                    HWND target = GetAncestor(hwnd, GA_ROOT);
                    if (!target)
                        target = GetParent(hwnd);

                    SendMessageW(
                        target,
                        WM_COMMAND,
                        MAKEWPARAM(
                            GetDlgCtrlID(hwnd),
                            BN_CLICKED
                        ),
                        reinterpret_cast<LPARAM>(hwnd)
                    );
                }

                return 0;
            }

            break;

        case WM_PAINT:
        {
            PAINTSTRUCT ps{};

            HDC hdc =
                BeginPaint(
                    hwnd,
                    &ps
                );

            RECT rc{};
            GetClientRect(hwnd, &rc);

            COLORREF background =
                COLOR_BUTTON;

            if (state && state->active)
                background = RGB(36, 43, 55);
            else if (state && state->hover)
                background = COLOR_BUTTON_HOV;

            if (state && state->pressed)
                background = RGB(44, 48, 58);

            HBRUSH brush =
                CreateSolidBrush(background);

            HRGN region =
                CreateRoundRectRgn(
                    0,
                    0,
                    rc.right,
                    rc.bottom,
                    10,
                    10
                );

            FillRgn(
                hdc,
                region,
                brush
            );

            DeleteObject(region);
            DeleteObject(brush);

            if (state && state->active)
            {
                HBRUSH accentBrush =
                    CreateSolidBrush(
                        COLOR_ACCENT
                    );

                RECT accent{};
                accent.left = 0;
                accent.top = 8;
                accent.right = 3;
                accent.bottom = rc.bottom - 8;

                FillRect(
                    hdc,
                    &accent,
                    accentBrush
                );

                DeleteObject(
                    accentBrush
                );
            }

            SetBkMode(
                hdc,
                TRANSPARENT
            );

            SetTextColor(
                hdc,
                COLOR_TEXT
            );

            HFONT oldFont = nullptr;

            if (state && state->font)
            {
                oldFont =
                    static_cast<HFONT>(
                        SelectObject(
                            hdc,
                            state->font
                        )
                        );
            }
            else if (g_fontMedium)
            {
                oldFont =
                    static_cast<HFONT>(
                        SelectObject(
                            hdc,
                            g_fontMedium
                        )
                    );
            }

            wchar_t text[512]{};

            GetWindowTextW(
                hwnd,
                text,
                512
            );

            RECT textRect = rc;
            textRect.left += 14; // padding
            textRect.right -= 14;

            DrawTextW(
                hdc,
                text,
                -1,
                &textRect,
                DT_LEFT |
                DT_VCENTER |
                DT_SINGLELINE
            );

            if (oldFont)
                SelectObject(
                    hdc,
                    oldFont
                );
            EndPaint(
                hwnd,
                &ps
            );

            return 0;

            EndPaint(
                hwnd,
                &ps
            );

            return 0;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_NCDESTROY:
            delete state;

            SetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA,
                0
            );

            break;

        case WM_TIMER:
            if (wParam == 1 && state)
            {
                KillTimer(hwnd, 1);
                state->pressed = false;
                InvalidateRect(hwnd, nullptr, TRUE);
            }

            return 0;
        }

        return DefWindowProcW(
            hwnd,
            message,
            wParam,
            lParam
        );
    }

    LRESULT CALLBACK BladePanelProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam
    )
    {
        COLORREF background =
            COLOR_PANEL;

        if (GetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA) != 0)
        {
            background =
                static_cast<COLORREF>(
                    GetWindowLongPtrW(
                        hwnd,
                        GWLP_USERDATA
                    )
                    );
        }

        switch (message)
        {
        case WM_NCCREATE:
        {
            auto* create =
                reinterpret_cast<
                CREATESTRUCTW*
                >(lParam);

            COLORREF color =
                COLOR_PANEL;

            if (create &&
                create->lpCreateParams)
            {
                color =
                    *reinterpret_cast<
                    COLORREF*
                    >(create->lpCreateParams);
            }

            SetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA,
                static_cast<LONG_PTR>(color)
            );

            return TRUE;
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
        {
            PAINTSTRUCT ps{};

            HDC hdc =
                BeginPaint(
                    hwnd,
                    &ps
                );

            RECT rc{};
            GetClientRect(hwnd, &rc);

            COLORREF bg =
                static_cast<COLORREF>(
                    GetWindowLongPtrW(
                        hwnd,
                        GWLP_USERDATA
                    )
                    );

            HBRUSH brush =
                CreateSolidBrush(bg);

            FillRect(
                hdc,
                &rc,
                brush
            );

            DeleteObject(brush);

            EndPaint(
                hwnd,
                &ps
            );

            return 0;
        }

        case WM_CTLCOLORSTATIC:
        {
            HDC hdc =
                reinterpret_cast<HDC>(wParam);

            HWND control =
                reinterpret_cast<HWND>(lParam);

            COLORREF textColor =
                COLOR_TEXT;

            HANDLE property =
                GetPropW(
                    control,
                    L"BladeTextColor"
                );

            if (property)
            {
                textColor =
                    static_cast<COLORREF>(
                        reinterpret_cast<
                        ULONG_PTR
                        >(property)
                        );
            }

            SetTextColor(
                hdc,
                textColor
            );

            SetBkMode(
                hdc,
                TRANSPARENT
            );

            COLORREF bg =
                static_cast<COLORREF>(
                    GetWindowLongPtrW(
                        hwnd,
                        GWLP_USERDATA
                    )
                    );

            if (bg == 0)
                bg = COLOR_PANEL;

            if (bg == COLOR_SIDEBAR)
                return reinterpret_cast<LRESULT>(
                    g_sidebarBrush
                    );

            if (bg == COLOR_PANEL_ALT)
                return reinterpret_cast<LRESULT>(
                    g_panelAltBrush
                    );

            return reinterpret_cast<LRESULT>(
                g_panelBrush
                );
        }

        case WM_CTLCOLOREDIT:
        {
            HDC hdc =
                reinterpret_cast<HDC>(wParam);

            SetTextColor(
                hdc,
                COLOR_TEXT
            );

            SetBkColor(
                hdc,
                COLOR_PANEL_ALT
            );

            return reinterpret_cast<LRESULT>(
                g_editBrush
                );
        }
        }

        return DefWindowProcW(
            hwnd,
            message,
            wParam,
            lParam
        );
    }

    LRESULT CALLBACK MainWindowProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam
    )
    {
        switch (message)
        {
        case WM_CREATE:
        {
            g_mainWindow = hwnd;

            g_font =
                CreateBladeFont(
                    17,
                    FW_NORMAL
                );

            g_fontSmall =
                CreateBladeFont(
                    14,
                    FW_NORMAL
                );

            g_fontMedium =
                CreateBladeFont(
                    16,
                    FW_SEMIBOLD
                );

            g_fontBold =
                CreateBladeFont(
                    18,
                    FW_BOLD
                );

            g_fontTitle =
                CreateBladeFont(
                    30,
                    FW_SEMIBOLD
                );

            g_fontBig =
                CreateBladeFont(
                    25,
                    FW_SEMIBOLD
                );

            g_fontHuge =
                CreateBladeFont(
                    31,
                    FW_BOLD
                );

            g_fontMono =
                CreateBladeFont(
                    14,
                    FW_NORMAL,
                    L"Consolas"
                );

            g_backgroundBrush =
                CreateSolidBrush(
                    COLOR_BACKGROUND
                );

            g_sidebarBrush =
                CreateSolidBrush(
                    COLOR_SIDEBAR
                );

            g_panelBrush =
                CreateSolidBrush(
                    COLOR_PANEL
                );

            g_panelAltBrush =
                CreateSolidBrush(
                    COLOR_PANEL_ALT
                );

            g_editBrush =
                CreateSolidBrush(
                    COLOR_PANEL_ALT
                );

            g_sidebar =
                CreateBladePanel(
                    hwnd,
                    0,
                    0,
                    SIDEBAR_WIDTH,
                    600,
                    COLOR_SIDEBAR
                );

            g_content =
                CreateBladePanel(
                    hwnd,
                    SIDEBAR_WIDTH,
                    0,
                    800,
                    600,
                    COLOR_BACKGROUND
                );

            g_footer =
                CreateBladePanel(
                    hwnd,
                    SIDEBAR_WIDTH,
                    600,
                    800,
                    FOOTER_HEIGHT,
                    COLOR_SIDEBAR
                );

            CreateSidebar();

            CreateLabel(
                g_footer,
                L"BladeAntivirus - Local protection engine",
                20,
                7,
                500,
                22,
                g_fontSmall,
                COLOR_DIM
            );

            CreateLabel(
                g_footer,
                L"PROTECTION ACTIVE",
                650,
                7,
                180,
                22,
                g_fontSmall,
                COLOR_GREEN
            );

            ShowDashboard();

            LayoutMainWindow();

            return 0;
        }

        case WM_SIZE:
            LayoutMainWindow();
            return 0;

        case WM_COMMAND:
        {
            int id =
                LOWORD(wParam);

            switch (id)
            {
            case ID_NAV_DASHBOARD:
                Navigate(Page::Dashboard);
                return 0;

            case ID_NAV_SCANNER:
                Navigate(Page::Scanner);
                return 0;

            case ID_NAV_UPDATES:
                Navigate(Page::Updates);
                return 0;

            case ID_NAV_ABOUT:
                Navigate(Page::About);
                return 0;

            case ID_SCAN_NOW:
                Navigate(Page::Scanner);
                SelectFile();
                return 0;

            case ID_SELECT_FILE:
                SelectFile();
                return 0;

            case ID_SCAN_FILE:
                ScanCurrentFile();
                return 0;

            case ID_CHECK_UPDATE:
                CheckUpdates();
                return 0;
            }

            break;
        }

        case WM_CTLCOLORSTATIC:
        {
            HDC hdc =
                reinterpret_cast<HDC>(wParam);

            SetTextColor(
                hdc,
                COLOR_TEXT
            );

            SetBkMode(
                hdc,
                TRANSPARENT
            );

            return reinterpret_cast<LRESULT>(
                g_backgroundBrush
                );
        }

        case WM_ERASEBKGND:
            return 1;

        case WM_PAINT:
        {
            PAINTSTRUCT ps{};

            HDC hdc =
                BeginPaint(
                    hwnd,
                    &ps
                );

            RECT rc{};
            GetClientRect(hwnd, &rc);

            FillRect(
                hdc,
                &rc,
                g_backgroundBrush
            );

            EndPaint(
                hwnd,
                &ps
            );

            return 0;
        }

        case WM_DESTROY:
        {
            if (g_backgroundBrush)
                DeleteObject(g_backgroundBrush);

            if (g_sidebarBrush)
                DeleteObject(g_sidebarBrush);

            if (g_panelBrush)
                DeleteObject(g_panelBrush);

            if (g_panelAltBrush)
                DeleteObject(g_panelAltBrush);

            if (g_editBrush)
                DeleteObject(g_editBrush);

            if (g_font)
                DeleteObject(g_font);

            if (g_fontSmall)
                DeleteObject(g_fontSmall);

            if (g_fontMedium)
                DeleteObject(g_fontMedium);

            if (g_fontBold)
                DeleteObject(g_fontBold);

            if (g_fontTitle)
                DeleteObject(g_fontTitle);

            if (g_fontBig)
                DeleteObject(g_fontBig);

            if (g_fontHuge)
                DeleteObject(g_fontHuge);

            if (g_fontMono)
                DeleteObject(g_fontMono);

            PostQuitMessage(0);

            return 0;
        }
        }

        return DefWindowProcW(
            hwnd,
            message,
            wParam,
            lParam
        );
    }
}

int WINAPI wWinMain(
    HINSTANCE hInstance,
    HINSTANCE,
    PWSTR,
    int nCmdShow
)
{
    g_instance = hInstance;

    WNDCLASSW buttonClass{};
    buttonClass.lpfnWndProc = BladeButtonProc;
    buttonClass.hInstance = hInstance;
    buttonClass.hCursor =
        LoadCursorW(
            nullptr,
            MAKEINTRESOURCEW(32512)
        );
    buttonClass.lpszClassName =
        BUTTON_CLASS;

    RegisterClassW(&buttonClass);

    WNDCLASSW panelClass{};
    panelClass.lpfnWndProc = BladePanelProc;
    panelClass.hInstance = hInstance;
    panelClass.hCursor =
        LoadCursorW(
            nullptr,
            MAKEINTRESOURCEW(32512)
        );
    panelClass.lpszClassName =
        PANEL_CLASS;

    RegisterClassW(&panelClass);

    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc =
        MainWindowProc;

    windowClass.hInstance =
        hInstance;

    windowClass.hCursor =
        LoadCursorW(
            nullptr,
            MAKEINTRESOURCEW(32512)
        );

    windowClass.hbrBackground =
        nullptr;

    windowClass.lpszClassName =
        WINDOW_CLASS;

    if (!RegisterClassW(&windowClass))
    {
        MessageBoxW(
            nullptr,
            L"Failed to register BladeAntivirus window class.",
            L"BladeAntivirus",
            MB_ICONERROR
        );

        return 1;
    }

    HWND hwnd =
        CreateWindowExW(
            0,
            WINDOW_CLASS,
            L"BladeAntivirus",
            WS_OVERLAPPEDWINDOW |
            WS_CLIPCHILDREN |
            WS_CLIPSIBLINGS,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1180,
            760,
            nullptr,
            nullptr,
            hInstance,
            nullptr
        );

    if (!hwnd)
    {
        MessageBoxW(
            nullptr,
            L"Failed to create BladeAntivirus window.",
            L"BladeAntivirus",
            MB_ICONERROR
        );

        return 1;
    }

    ShowWindow(
        hwnd,
        nCmdShow
    );

    UpdateWindow(hwnd);

    MSG message{};

    while (GetMessageW(
        &message,
        nullptr,
        0,
        0
    ) > 0)
    {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return static_cast<int>(
        message.wParam
        );
}