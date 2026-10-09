
cmake_minimum_required(VERSION 3.20)

project(BladeAntivirus VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(IMGUI_DIR "D:/ImGui")

if(NOT EXISTS "${IMGUI_DIR}/imgui.cpp")
    message(FATAL_ERROR "Dear ImGui not found in D:/ImGui")
endif()

add_executable(BladeAntivirus WIN32
    src/main.cpp

    src/scanner/scanner.cpp
    src/scanner/hash_detector.cpp
    src/updater/updater.cpp
    src/signs/signs.cpp

    "${IMGUI_DIR}/imgui.cpp"
    "${IMGUI_DIR}/imgui_draw.cpp"
    "${IMGUI_DIR}/imgui_tables.cpp"
    "${IMGUI_DIR}/imgui_widgets.cpp"

    "${IMGUI_DIR}/backends/imgui_impl_win32.cpp"
    "${IMGUI_DIR}/backends/imgui_impl_dx11.cpp"
)

target_include_directories(BladeAntivirus PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/scanner"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/updater"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/signs"
    "${IMGUI_DIR}"
    "${IMGUI_DIR}/backends"
)

target_compile_definitions(BladeAntivirus PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(BladeAntivirus PRIVATE
    d3d11
    dxgi
    dwmapi
    bcrypt
    winhttp
    comdlg32
)

if(MSVC)
    target_compile_options(BladeAntivirus PRIVATE
        /W4
        /permissive-
    )
endif()
