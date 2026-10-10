
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commdlg.h>
#include <d3d11.h>
#include <dxgi.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <system_error>
#include <fstream>
#include <map>
#include <ctime>

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hwnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam
);

#include "scanner/scanner.h"
#include "signs/signs.hpp"
#include "updater/updater.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "comdlg32.lib")

namespace
{
    constexpr wchar_t WINDOW_CLASS[] = L"BladeAntivirusImGuiWindow";

    enum class Page
    {
        Dashboard,
        Scanner,
        Updates,
        About
    };

    struct ScanState
    {
        ScanResult scan{};
        SignsResult signs{};
        std::string error;
        bool valid = false;
        bool detected = false;
    };

    ID3D11Device* g_device = nullptr;
    ID3D11DeviceContext* g_context = nullptr;
    IDXGISwapChain* g_swapChain = nullptr;
    ID3D11RenderTargetView* g_renderTarget = nullptr;

    HWND g_window = nullptr;
    Page g_page = Page::Dashboard;

    std::wstring g_selectedPath;
    std::string g_selectedPathForEngine;
    std::string g_databasePath;
    std::string g_urlPath;
    std::string g_ipPath;
    std::string g_updateStatePath;

    std::mutex g_stateMutex;
    ScanState g_scanState;
    std::string g_scanStatus = "Ready to scan";
    std::string g_updateStatus = "Updates are not configured";

    std::atomic<bool> g_scanning{ false };
    std::atomic<bool> g_updating{ false };

    std::thread g_scanThread;
    std::thread g_updateThread;

    bool g_imguiInitialized = false;

    std::string WideToUtf8(const std::wstring& value)
    {
        if (value.empty())
            return {};

        const int size = WideCharToMultiByte(
            CP_UTF8, 0, value.data(),
            static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);

        if (size <= 0)
            return {};

        std::string result(static_cast<size_t>(size), '\0');

        WideCharToMultiByte(
            CP_UTF8, 0, value.data(),
            static_cast<int>(value.size()),
            result.data(), size, nullptr, nullptr);

        return result;
    }

    std::string WideToAnsi(const std::wstring& value)
    {
        if (value.empty())
            return {};

        const int size = WideCharToMultiByte(
            CP_ACP, 0, value.data(),
            static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);

        if (size <= 0)
            return {};

        std::string result(static_cast<size_t>(size), '\0');

        WideCharToMultiByte(
            CP_ACP, 0, value.data(),
            static_cast<int>(value.size()),
            result.data(), size, nullptr, nullptr);

        return result;
    }

    std::wstring GetExecutableDirectory()
    {
        wchar_t buffer[32768]{};

        const DWORD length = GetModuleFileNameW(
            nullptr, buffer, static_cast<DWORD>(std::size(buffer)));

        if (length == 0 || length >= std::size(buffer))
            return L".";

        return std::filesystem::path(buffer).parent_path().wstring();
    }

    std::filesystem::path FindDatabaseFile(const wchar_t* filename)
    {
        const std::filesystem::path executableDir(
            GetExecutableDirectory());

        const std::filesystem::path candidates[] =
        {
            executableDir / L"database" / filename,
            executableDir / L"..\\..\\..\\database" / filename,
            std::filesystem::current_path() / L"database" / filename
        };

        for (const auto& candidate : candidates)
        {
            std::error_code ec;

            if (std::filesystem::is_regular_file(candidate, ec))
            {
                auto resolved =
                    std::filesystem::weakly_canonical(candidate, ec);

                if (!ec)
                    return resolved;

                return candidate;
            }
        }

        return std::filesystem::path(GetExecutableDirectory())
            / L"database" / filename;
    }

    std::string GetDatabasePath()
    {
        return WideToAnsi(FindDatabaseFile(L"hashes.txt").wstring());
    }

    std::string GetUrlDatabasePath()
    {
        return WideToAnsi(FindDatabaseFile(L"url.txt").wstring());
    }

    std::string GetIpDatabasePath()
    {
        return WideToAnsi(FindDatabaseFile(L"ip.txt").wstring());
    }

    std::string GetUpdateStatePath()
    {
        return WideToAnsi(
            FindDatabaseFile(L"update_state.txt").wstring());
    }

    std::map<std::string, long long> LoadUpdateState(const std::string& statePath)
    {
        std::map<std::string, long long> state;
        std::ifstream file(statePath);

        std::string key;
        long long timestamp = 0;

        while (file >> key >> timestamp)
            state[key] = timestamp;

        return state;
    }

    bool UpdatesDue()
    {
        constexpr long long UPDATE_INTERVAL_SECONDS = 86100; // 23h55m

        const auto state = LoadUpdateState(g_updateStatePath);
        const long long now = static_cast<long long>(std::time(nullptr));

        const char* keys[] = { "sha256", "urlhaus", "threatfox" };

        for (const char* key : keys)
        {
            const auto it = state.find(key);

            if (it == state.end())
                return true; // no record -> due

            if (now - it->second >= UPDATE_INTERVAL_SECONDS)
                return true; // due
        }

        return false; // none due
    }

    void SetScanStatus(const std::string& status)
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        g_scanStatus = status;
    }

    void SetUpdateStatus(const std::string& status)
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        g_updateStatus = status;
    }

    std::string GetScanStatus()
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        return g_scanStatus;
    }

    std::string GetUpdateStatus()
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        return g_updateStatus;
    }

    ScanState GetScanState()
    {
        std::lock_guard<std::mutex> lock(g_stateMutex);
        return g_scanState;
    }

    bool CreateRenderTarget()
    {
        ID3D11Texture2D* backBuffer = nullptr;

        const HRESULT result = g_swapChain->GetBuffer(
            0, IID_PPV_ARGS(&backBuffer));

        if (FAILED(result))
            return false;

        const HRESULT viewResult = g_device->CreateRenderTargetView(
            backBuffer, nullptr, &g_renderTarget);

        backBuffer->Release();

        return SUCCEEDED(viewResult);
    }

    void CleanupRenderTarget()
    {
        if (g_renderTarget)
        {
            g_renderTarget->Release();
            g_renderTarget = nullptr;
        }
    }

    bool CreateDeviceD3D(HWND hwnd)
    {
        DXGI_SWAP_CHAIN_DESC desc{};
        desc.BufferCount = 2;
        desc.BufferDesc.Width = 0;
        desc.BufferDesc.Height = 0;
        desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.BufferDesc.RefreshRate.Numerator = 60;
        desc.BufferDesc.RefreshRate.Denominator = 1;
        desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        desc.OutputWindow = hwnd;
        desc.SampleDesc.Count = 1;
        desc.Windowed = TRUE;
        desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        const D3D_FEATURE_LEVEL levels[] =
        {
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_0
        };

        D3D_FEATURE_LEVEL selectedLevel{};

        HRESULT result = D3D11CreateDeviceAndSwapChain(
            nullptr,
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,
            0,
            levels,
            static_cast<UINT>(std::size(levels)),
            D3D11_SDK_VERSION,
            &desc,
            &g_swapChain,
            &g_device,
            &selectedLevel,
            &g_context);

        if (result == DXGI_ERROR_UNSUPPORTED)
        {
            result = D3D11CreateDeviceAndSwapChain(
                nullptr,
                D3D_DRIVER_TYPE_WARP,
                nullptr,
                0,
                levels,
                static_cast<UINT>(std::size(levels)),
                D3D11_SDK_VERSION,
                &desc,
                &g_swapChain,
                &g_device,
                &selectedLevel,
                &g_context);
        }

        if (FAILED(result))
            return false;

        return CreateRenderTarget();
    }

    void CleanupDeviceD3D()
    {
        CleanupRenderTarget();

        if (g_swapChain)
        {
            g_swapChain->Release();
            g_swapChain = nullptr;
        }

        if (g_context)
        {
            g_context->Release();
            g_context = nullptr;
        }

        if (g_device)
        {
            g_device->Release();
            g_device = nullptr;
        }
    }

    void ApplyStyle()
    {
        ImGuiStyle& style = ImGui::GetStyle();

        style.WindowRounding = 10.0f;
        style.ChildRounding = 10.0f;
        style.FrameRounding = 7.0f;
        style.PopupRounding = 8.0f;
        style.ScrollbarRounding = 8.0f;
        style.GrabRounding = 7.0f;
        style.TabRounding = 7.0f;

        style.WindowPadding = ImVec2(20.0f, 20.0f);
        style.FramePadding = ImVec2(13.0f, 10.0f);
        style.ItemSpacing = ImVec2(10.0f, 10.0f);
        style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);

        ImVec4* colors = style.Colors;

        colors[ImGuiCol_Text] = ImVec4(0.94f, 0.95f, 0.97f, 1.00f);
        colors[ImGuiCol_TextDisabled] = ImVec4(0.48f, 0.51f, 0.57f, 1.00f);
        colors[ImGuiCol_WindowBg] = ImVec4(0.043f, 0.047f, 0.059f, 1.00f);
        colors[ImGuiCol_ChildBg] = ImVec4(0.063f, 0.071f, 0.086f, 1.00f);
        colors[ImGuiCol_PopupBg] = ImVec4(0.075f, 0.082f, 0.098f, 1.00f);
        colors[ImGuiCol_Border] = ImVec4(0.15f, 0.17f, 0.20f, 1.00f);
        colors[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.11f, 0.14f, 1.00f);
        colors[ImGuiCol_FrameBgHovered] = ImVec4(0.14f, 0.16f, 0.20f, 1.00f);
        colors[ImGuiCol_FrameBgActive] = ImVec4(0.17f, 0.19f, 0.24f, 1.00f);
        colors[ImGuiCol_Button] = ImVec4(0.10f, 0.12f, 0.16f, 1.00f);
        colors[ImGuiCol_ButtonHovered] = ImVec4(0.15f, 0.19f, 0.26f, 1.00f);
        colors[ImGuiCol_ButtonActive] = ImVec4(0.18f, 0.23f, 0.32f, 1.00f);
        colors[ImGuiCol_Header] = ImVec4(0.11f, 0.15f, 0.22f, 1.00f);
        colors[ImGuiCol_HeaderHovered] = ImVec4(0.13f, 0.18f, 0.27f, 1.00f);
        colors[ImGuiCol_HeaderActive] = ImVec4(0.15f, 0.21f, 0.32f, 1.00f);
        colors[ImGuiCol_CheckMark] = ImVec4(0.20f, 0.51f, 1.00f, 1.00f);
        colors[ImGuiCol_SliderGrab] = ImVec4(0.20f, 0.51f, 1.00f, 1.00f);
        colors[ImGuiCol_SliderGrabActive] = ImVec4(0.34f, 0.60f, 1.00f, 1.00f);
        colors[ImGuiCol_Separator] = ImVec4(0.15f, 0.17f, 0.20f, 1.00f);
        colors[ImGuiCol_ScrollbarBg] = ImVec4(0.04f, 0.05f, 0.07f, 1.00f);
        colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.20f, 0.22f, 0.27f, 1.00f);
    }

    void SelectFile()
    {
        OPENFILENAMEW dialog{};
        wchar_t fileName[32768]{};

        dialog.lStructSize = sizeof(dialog);
        dialog.hwndOwner = g_window;
        dialog.lpstrFile = fileName;
        dialog.nMaxFile = static_cast<DWORD>(std::size(fileName));
        dialog.lpstrFilter =
            L"Executable files (*.exe;*.dll)\0*.exe;*.dll\0"
            L"All files (*.*)\0*.*\0";
        dialog.nFilterIndex = 1;
        dialog.Flags = OFN_FILEMUSTEXIST |
            OFN_PATHMUSTEXIST |
            OFN_NOCHANGEDIR;

        if (GetOpenFileNameW(&dialog))
        {
            g_selectedPath = fileName;
            g_selectedPathForEngine = WideToAnsi(g_selectedPath);

            {
                std::lock_guard<std::mutex> lock(g_stateMutex);
                g_scanStatus = "File selected. Ready to scan.";
                g_scanState = ScanState{};
            }
        }
    }

    void StartScan()
    {
        if (g_scanning.load())
            return;

        if (g_selectedPath.empty())
        {
            SetScanStatus("Select a file before starting the scan.");
            return;
        }

        if (g_scanThread.joinable())
            g_scanThread.join();

        const std::string filePath = g_selectedPathForEngine;
        const std::string databasePath = g_databasePath;

        {
            std::lock_guard<std::mutex> lock(g_stateMutex);
            g_scanStatus = "Scanning file...";
            g_scanState = ScanState{};
        }

        g_scanning.store(true);

        g_scanThread = std::thread([filePath, databasePath]()
            {
                ScanState result;

                try
                {
                    Scanner scanner;

                    if (!scanner.initialize(databasePath))
                    {
                        result.error =
                            "Could not initialize the hash scanner. "
                            "Check that database/hashes.txt exists and is readable.";
                    }
                    else
                    {
                        result.scan = scanner.scan(filePath);

                        SignsEngine engine;
                        result.signs = engine.analyze(filePath);

                        result.detected =
                            result.scan.hashMatch ||
                            result.signs.verdict == "MALICIOUS" ||
                            result.signs.verdict == "SUSPICIOUS";

                        result.valid = true;
                    }
                }
                catch (const std::exception& ex)
                {
                    result.error = std::string("Scan failed: ") + ex.what();
                }
                catch (...)
                {
                    result.error = "Scan failed due to an unexpected error.";
                }

                {
                    std::lock_guard<std::mutex> lock(g_stateMutex);
                    g_scanState = std::move(result);

                    if (!g_scanState.error.empty())
                        g_scanStatus = "Scan failed";
                    else if (g_scanState.detected)
                        g_scanStatus = "Suspicious indicators found";
                    else
                        g_scanStatus = "Scan completed";
                }

                g_scanning.store(false);
            });
    }

    void StartUpdate(bool force = false)
    {
        if (g_updating.load())
            return;

        if (g_updateThread.joinable())
            g_updateThread.join();

        const std::string sha256Path = g_databasePath;
        const std::string urlPath = g_urlPath;
        const std::string ipPath = g_ipPath;
        const std::string statePath = g_updateStatePath;

        SetUpdateStatus("Checking update schedule...");
        g_updating.store(true);

        g_updateThread = std::thread(
            [sha256Path, urlPath, ipPath, statePath, force]()
            {
                std::string status;

                try
                {
                    Updater updater;

                    updater.updateFeeds(
                        sha256Path,
                        urlPath,
                        ipPath,
                        statePath,
                        status,
                        force);
                }
                catch (const std::exception& ex)
                {
                    status = std::string("Update failed: ") + ex.what();
                }
                catch (...)
                {
                    status = "Update failed due to an unexpected error.";
                }

                if (status.empty())
                    status = "Updater finished without a status.";

                SetUpdateStatus(status);
                g_updating.store(false);
            });
    }

    bool NavButton(const char* label, Page page)
    {
        const bool active = g_page == page;

        if (active)
        {
            ImGui::PushStyleColor(
                ImGuiCol_Button,
                ImVec4(0.12f, 0.20f, 0.34f, 1.0f));

            ImGui::PushStyleColor(
                ImGuiCol_ButtonHovered,
                ImVec4(0.15f, 0.23f, 0.38f, 1.0f));
        }

        const bool clicked = ImGui::Button(label, ImVec2(-1.0f, 44.0f));

        if (active)
            ImGui::PopStyleColor(2);

        if (clicked)
            g_page = page;

        return clicked;
    }

    void DrawSidebar()
    {
        ImGui::BeginChild(
            "Sidebar",
            ImVec2(225.0f, 0.0f),
            ImGuiChildFlags_Borders);

        ImGui::Dummy(ImVec2(0.0f, 8.0f));

        ImGui::TextColored(
            ImVec4(0.24f, 0.53f, 1.0f, 1.0f),
            "BLADE");

        ImGui::SameLine();
        ImGui::TextDisabled("ANTIVIRUS");

        ImGui::Separator();
        ImGui::Dummy(ImVec2(0.0f, 12.0f));

        NavButton("Dashboard", Page::Dashboard);
        NavButton("Scanner", Page::Scanner);
        NavButton("Updates", Page::Updates);
        NavButton("About", Page::About);

        ImGui::SetCursorPosY(
            ImGui::GetWindowHeight() - 115.0f);

        ImGui::Separator();
        ImGui::TextDisabled("DETECTION ENGINES");
        ImGui::BulletText("SHA-256 database");
        ImGui::BulletText("Static signs");
        ImGui::BulletText("PE inspection");

        ImGui::Dummy(ImVec2(0.0f, 8.0f));
        ImGui::TextColored(
            ImVec4(0.94f, 0.70f, 0.25f, 1.0f),
            "Manual scanning only");

        ImGui::EndChild();
    }

    void DrawDashboard()
    {
        ImGui::TextDisabled("SECURITY OVERVIEW");
        ImGui::Spacing();
        ImGui::Text("Dashboard");
        ImGui::TextWrapped(
            "Inspect a file locally with the available detection engines.");

        ImGui::Dummy(ImVec2(0.0f, 12.0f));

        ImGui::BeginChild(
            "ProtectionCard",
            ImVec2(0.0f, 155.0f),
            ImGuiChildFlags_Borders);

        ImGui::TextColored(
            ImVec4(0.30f, 0.68f, 1.0f, 1.0f),
            "BLADEANTIVIRUS");

        ImGui::Spacing();
        ImGui::Text("Manual scan engine");
        ImGui::TextDisabled(
            "SHA-256 matching, PE inspection and static indicators");

        ImGui::Spacing();

        ImGui::TextColored(
            ImVec4(0.95f, 0.72f, 0.26f, 1.0f),
            "Real-time protection is not enabled");

        ImGui::TextDisabled(
            "This application does not currently block files in the background.");

        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::Text("Detection engines");

        const float available = ImGui::GetContentRegionAvail().x;
        const float gap = 10.0f;
        const float cardWidth = (available - gap * 2.0f) / 3.0f;

        ImGui::BeginChild(
            "HashCard",
            ImVec2(cardWidth, 105.0f),
            ImGuiChildFlags_Borders);

        ImGui::TextDisabled("HASH DATABASE");
        ImGui::Spacing();
        ImGui::Text("SHA-256");
        ImGui::TextDisabled("Local indicators");

        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild(
            "SignsCard",
            ImVec2(cardWidth, 105.0f),
            ImGuiChildFlags_Borders);

        ImGui::TextDisabled("STATIC SIGNS");
        ImGui::Spacing();
        ImGui::Text("Heuristics");
        ImGui::TextDisabled("Potential indicators");

        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild(
            "PeCard",
            ImVec2(cardWidth, 105.0f),
            ImGuiChildFlags_Borders);

        ImGui::TextDisabled("FILE FORMAT");
        ImGui::Spacing();
        ImGui::Text("PE analysis");
        ImGui::TextDisabled("Executable inspection");

        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::Text("Quick action");

        if (ImGui::Button("Select file and scan", ImVec2(240.0f, 46.0f)))
        {
            SelectFile();

            if (!g_selectedPath.empty())
            {
                g_page = Page::Scanner;
                StartScan();
            }
        }

        ImGui::SameLine();

        if (ImGui::Button("Open scanner", ImVec2(180.0f, 46.0f)))
            g_page = Page::Scanner;
    }

    void DrawScanner()
    {
        ImGui::TextDisabled("LOCAL FILE ANALYSIS");
        ImGui::Spacing();
        ImGui::Text("Scanner");
        ImGui::TextWrapped(
            "Select an executable or another file to inspect it.");

        ImGui::Spacing();

        ImGui::BeginChild(
            "TargetCard",
            ImVec2(0.0f, 145.0f),
            ImGuiChildFlags_Borders);

        ImGui::TextDisabled("TARGET FILE");
        ImGui::Spacing();

        const std::string displayPath =
            g_selectedPath.empty()
            ? "No file selected"
            : WideToUtf8(g_selectedPath);

        ImGui::TextWrapped("%s", displayPath.c_str());

        ImGui::Spacing();

        if (ImGui::Button("Select file", ImVec2(150.0f, 40.0f)))
            SelectFile();

        ImGui::SameLine();

        if (g_scanning.load())
        {
            ImGui::BeginDisabled();
            ImGui::Button("Scanning...", ImVec2(170.0f, 40.0f));
            ImGui::EndDisabled();
        }
        else
        {
            if (ImGui::Button("Scan file", ImVec2(170.0f, 40.0f)))
                StartScan();
        }

        ImGui::EndChild();

        ImGui::Spacing();

        const std::string status = GetScanStatus();

        ImGui::Text("Status:");
        ImGui::SameLine();

        if (g_scanning.load())
        {
            ImGui::TextColored(
                ImVec4(0.30f, 0.60f, 1.0f, 1.0f),
                "%s", status.c_str());

            ImGui::SameLine();
            ImGui::TextDisabled("Please wait...");
        }
        else
        {
            const ScanState state = GetScanState();

            const ImVec4 statusColor =
                !state.error.empty()
                ? ImVec4(0.92f, 0.30f, 0.30f, 1.0f)
                : state.detected
                ? ImVec4(0.95f, 0.35f, 0.32f, 1.0f)
                : ImVec4(0.35f, 0.78f, 0.52f, 1.0f);

            ImGui::TextColored(statusColor, "%s", status.c_str());
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Scan results");

        ImGui::BeginChild(
            "Results",
            ImVec2(0.0f, 0.0f),
            ImGuiChildFlags_Borders);

        const ScanState state = GetScanState();

        if (g_scanning.load())
        {
            ImGui::TextWrapped(
                "Analysis is running in the background thread. "
                "The interface remains responsive.");
        }
        else if (!state.error.empty())
        {
            ImGui::TextColored(
                ImVec4(0.95f, 0.34f, 0.34f, 1.0f),
                "Scan error");

            ImGui::Spacing();
            ImGui::TextWrapped("%s", state.error.c_str());
        }
        else if (!state.valid)
        {
            ImGui::TextDisabled(
                "Select a file and start a scan to see the results here.");
        }
        else
        {
            if (state.detected)
            {
                ImGui::TextColored(
                    ImVec4(0.95f, 0.30f, 0.30f, 1.0f),
                    "SUSPICIOUS INDICATORS FOUND");
            }
            else
            {
                ImGui::TextColored(
                    ImVec4(0.35f, 0.80f, 0.53f, 1.0f),
                    "NO MATCHING INDICATORS FOUND");
            }

            ImGui::Spacing();
            ImGui::Separator();

            ImGui::Text("File:");
            ImGui::TextWrapped(
                "%s", WideToUtf8(g_selectedPath).c_str());

            ImGui::Spacing();
            ImGui::Text("SHA-256 engine");

            ImGui::BulletText(
                "Hash match: %s",
                state.scan.hashMatch ? "YES" : "NO");

            ImGui::BulletText(
                "PE file: %s",
                state.scan.isPE ? "YES" : "NO");

            ImGui::BulletText(
                "Engine verdict: %s",
                state.scan.verdict.empty()
                ? "Not provided"
                : state.scan.verdict.c_str());

            if (!state.scan.sha256.empty())
            {
                ImGui::Text("SHA-256:");
                ImGui::TextWrapped(
                    "%s", state.scan.sha256.c_str());
            }

            ImGui::Spacing();
            ImGui::Separator();

            ImGui::Text("Static signs");
            ImGui::BulletText(
                "Score: %d", state.signs.score);

            ImGui::BulletText(
                "Verdict: %s",
                state.signs.verdict.empty()
                ? "Not provided"
                : state.signs.verdict.c_str());

            if (state.signs.matches.empty())
            {
                ImGui::TextDisabled("No static signs matched.");
            }
            else
            {
                for (const auto& match : state.signs.matches)
                {
                    ImGui::Spacing();

                    ImGui::Text(
                        "%s (+%d)",
                        match.name.c_str(),
                        match.score);

                    ImGui::TextWrapped(
                        "%s", match.description.c_str());
                }
            }

            ImGui::Spacing();
            ImGui::Separator();

            ImGui::TextDisabled(
                "A clean result does not guarantee that a file is safe. "
                "Static heuristics can produce false positives and false negatives.");
        }

        ImGui::EndChild();
    }

    void DrawUpdates()
    {
        ImGui::TextDisabled("DATABASE MANAGEMENT");
        ImGui::Spacing();
        ImGui::Text("Updates");
        ImGui::TextWrapped(
            "BladeAntivirus updates local SHA-256, URL and IP databases "
            "from public threat-intelligence feeds. Automatic updates "
            "are checked when the application starts.");

        ImGui::Spacing();

        ImGui::BeginChild(
            "UpdateCard",
            ImVec2(0.0f, 185.0f),
            ImGuiChildFlags_Borders);

        ImGui::TextDisabled("THREAT DATABASE");
        ImGui::Spacing();
        ImGui::Text("SHA-256 indicators");
        ImGui::TextDisabled("Local database: database/hashes.txt");

        ImGui::Spacing();

        if (g_updating.load())
        {
            ImGui::BeginDisabled();
            ImGui::Button("Updating...", ImVec2(220.0f, 44.0f));
            ImGui::EndDisabled();
        }
        else
        {
            if (!UpdatesDue())
            {
                ImGui::BeginDisabled();
                ImGui::Button("Check for updates", ImVec2(220.0f, 44.0f));
                ImGui::EndDisabled();
            }
            else
            {
                if (ImGui::Button(
                    "Check for updates", ImVec2(220.0f, 44.0f)))
                {
                    // Double-check before starting update to ensure the
                    // button cannot trigger action when not due.
                    if (UpdatesDue())
                        StartUpdate(true);
                }
            }
        }

        ImGui::Spacing();

        const std::string status = GetUpdateStatus();

        ImGui::TextWrapped("%s", status.c_str());

        ImGui::EndChild();

        ImGui::Spacing();

        // Configuration information removed; updater uses local feed files.
    }

    void DrawAbout()
    {
        ImGui::TextDisabled("APPLICATION INFORMATION");
        ImGui::Spacing();
        ImGui::Text("About BladeAntivirus");

        ImGui::Spacing();

        ImGui::BeginChild(
            "AboutCard",
            ImVec2(0.0f, 190.0f),
            ImGuiChildFlags_Borders);

        ImGui::TextColored(
            ImVec4(0.24f, 0.53f, 1.0f, 1.0f),
            "BLADE");

        ImGui::SameLine();
        ImGui::Text("ANTIVIRUS");

        ImGui::Spacing();
        ImGui::Text("Version 1.0.0");

        ImGui::TextWrapped(
            "Native Windows application for local file inspection.");

        ImGui::Spacing();
        ImGui::TextDisabled(
            "Interface: Dear ImGui + DirectX 11");

        ImGui::EndChild();

        ImGui::Spacing();
        ImGui::Text("Components");

        ImGui::BulletText("SHA-256 hash detection");
        ImGui::BulletText("PE file inspection");
        ImGui::BulletText("Static sign analysis");
        ImGui::BulletText("WinHTTP database updater");

        ImGui::Spacing();

        ImGui::TextColored(
            ImVec4(0.95f, 0.72f, 0.26f, 1.0f),
            "Real-time file blocking is not implemented.");
    }

    void DrawInterface()
    {
        ImGuiViewport* viewport = ImGui::GetMainViewport();

        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(
            ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));

        constexpr ImGuiWindowFlags flags =
            ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus |
            ImGuiWindowFlags_NoNavFocus;

        ImGui::Begin("BladeAntivirusRoot", nullptr, flags);
        ImGui::PopStyleVar(3);

        DrawSidebar();

        ImGui::SameLine(0.0f, 0.0f);

        ImGui::BeginChild(
            "MainContent",
            ImVec2(0.0f, 0.0f),
            ImGuiChildFlags_None);

        ImGui::TextColored(
            ImVec4(0.24f, 0.53f, 1.0f, 1.0f),
            "BLADEANTIVIRUS");

        ImGui::SameLine();
        ImGui::TextDisabled("/");

        switch (g_page)
        {
        case Page::Dashboard:
            DrawDashboard();
            break;

        case Page::Scanner:
            DrawScanner();
            break;

        case Page::Updates:
            DrawUpdates();
            break;

        case Page::About:
            DrawAbout();
            break;
        }

        ImGui::EndChild();
        ImGui::End();
    }

    LRESULT WINAPI WindowProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam)
    {
        if (g_imguiInitialized)
        {
            const LRESULT imguiResult =
                ImGui_ImplWin32_WndProcHandler(
                    hwnd, message, wParam, lParam);

            if (imguiResult)
                return imguiResult;
        }

        switch (message)
        {
        case WM_SIZE:
            if (g_device &&
                wParam != SIZE_MINIMIZED &&
                g_swapChain)
            {
                CleanupRenderTarget();

                const HRESULT result = g_swapChain->ResizeBuffers(
                    0,
                    LOWORD(lParam),
                    HIWORD(lParam),
                    DXGI_FORMAT_UNKNOWN,
                    0);

                if (SUCCEEDED(result))
                    CreateRenderTarget();
            }
            return 0;

        case WM_SYSCOMMAND:
            if ((wParam & 0xFFF0) == SC_KEYMENU)
                return 0;
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
}

int WINAPI wWinMain(
    HINSTANCE instance,
    HINSTANCE,
    PWSTR,
    int showCommand)
{
    g_databasePath = GetDatabasePath();
    g_urlPath = GetUrlDatabasePath();
    g_ipPath = GetIpDatabasePath();
    g_updateStatePath = GetUpdateStatePath();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = WINDOW_CLASS;

    if (!RegisterClassExW(&wc))
    {
        MessageBoxW(
            nullptr,
            L"Could not register the application window.",
            L"BladeAntivirus",
            MB_ICONERROR);

        return 1;
    }

    g_window = CreateWindowExW(
        0,
        WINDOW_CLASS,
        L"BladeAntivirus",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1360,
        850,
        nullptr,
        nullptr,
        instance,
        nullptr);

    if (!g_window)
    {
        UnregisterClassW(WINDOW_CLASS, instance);

        MessageBoxW(
            nullptr,
            L"Could not create the application window.",
            L"BladeAntivirus",
            MB_ICONERROR);

        return 1;
    }

    if (!CreateDeviceD3D(g_window))
    {
        CleanupDeviceD3D();
        DestroyWindow(g_window);
        UnregisterClassW(WINDOW_CLASS, instance);

        MessageBoxW(
            nullptr,
            L"Could not initialize DirectX 11.",
            L"BladeAntivirus",
            MB_ICONERROR);

        return 1;
    }

    ShowWindow(g_window, showCommand);
    UpdateWindow(g_window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ApplyStyle();

    if (!ImGui_ImplWin32_Init(g_window) ||
        !ImGui_ImplDX11_Init(g_device, g_context))
    {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();

        CleanupDeviceD3D();
        DestroyWindow(g_window);
        UnregisterClassW(WINDOW_CLASS, instance);

        MessageBoxW(
            nullptr,
            L"Could not initialize the ImGui backends.",
            L"BladeAntivirus",
            MB_ICONERROR);

        return 1;
    }

    g_imguiInitialized = true;

    StartUpdate(false);

    MSG message{};

    while (message.message != WM_QUIT)
    {
        if (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        DrawInterface();

        ImGui::Render();

        const float clearColor[4] =
        {
            0.043f,
            0.047f,
            0.059f,
            1.0f
        };

        g_context->OMSetRenderTargets(1, &g_renderTarget, nullptr);
        g_context->ClearRenderTargetView(
            g_renderTarget, clearColor);

        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_swapChain->Present(1, 0);
    }

    g_imguiInitialized = false;

    if (g_scanThread.joinable())
        g_scanThread.join();

    if (g_updateThread.joinable())
        g_updateThread.join();

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();

    DestroyWindow(g_window);
    UnregisterClassW(WINDOW_CLASS, instance);

    return static_cast<int>(message.wParam);
}
