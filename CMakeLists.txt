
cmake_minimum_required(VERSION 3.25)

project(BladeAntivirus VERSION 1.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.8 REQUIRED COMPONENTS
    Core
    Gui
    Qml
    Quick
    QuickControls2
    Widgets
    Network
)

qt_standard_project_setup(REQUIRES 6.8)

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(SRC_DIR "${PROJECT_ROOT}/src")
set(MAIN_QML "${SRC_DIR}/qml/Main.qml")

qt_add_executable(BladeAntivirus
     "${SRC_DIR}/appicon.rc"

    "${SRC_DIR}/main.cpp"

    "${SRC_DIR}/app/antiviruscontroller.h"
    "${SRC_DIR}/app/antiviruscontroller.cpp"

    "${SRC_DIR}/scanner/scanner.h"
    "${SRC_DIR}/scanner/scanner.cpp"
    "${SRC_DIR}/scanner/hash_detector.h"
    "${SRC_DIR}/scanner/hash_detector.cpp"

    "${SRC_DIR}/scanner/pe_analyzer.h"
    "${SRC_DIR}/scanner/pe_analyzer.cpp"

    "${SRC_DIR}/scanner/scan_cache.h"
    "${SRC_DIR}/scanner/scan_cache.cpp"

    "${SRC_DIR}/scanner/scan_policy.h"
    "${SRC_DIR}/scanner/scan_policy.cpp"

    "${SRC_DIR}/scanner/pending_queue.h"
    "${SRC_DIR}/scanner/pending_queue.cpp"

    "${SRC_DIR}/updater/updater.h"
    "${SRC_DIR}/updater/updater.cpp"
)

set(OPTIONAL_SOURCES
    "${SRC_DIR}/signs/signs.hpp"
    "${SRC_DIR}/signs/signs.cpp"

    "${SRC_DIR}/heuristic/heuristic_detector.h"
    "${SRC_DIR}/heuristic/heuristic_detector.cpp"

    "${SRC_DIR}/behavior/behavior_monitor.h"
    "${SRC_DIR}/behavior/behavior_monitor.cpp"

    "${SRC_DIR}/realtime/realtime_protection.h"
    "${SRC_DIR}/realtime/realtime_protection.cpp"

    "${SRC_DIR}/scan/scan_controller.h"
    "${SRC_DIR}/scan/scan_controller.cpp"

    "${SRC_DIR}/settings/app_settings.h"
    "${SRC_DIR}/settings/app_settings.cpp"

    "${SRC_DIR}/database/database_manager.h"
    "${SRC_DIR}/database/database_manager.cpp"
)

foreach(SOURCE_FILE IN LISTS OPTIONAL_SOURCES)
    if(EXISTS "${SOURCE_FILE}")
        target_sources(BladeAntivirus PRIVATE "${SOURCE_FILE}")
    endif()
endforeach()

target_include_directories(BladeAntivirus PRIVATE
    "${SRC_DIR}"
    "${SRC_DIR}/app"
    "${SRC_DIR}/scanner"
    "${SRC_DIR}/updater"
    "${SRC_DIR}/signs"
    "${SRC_DIR}/heuristic"
    "${SRC_DIR}/behavior"
    "${SRC_DIR}/realtime"
    "${SRC_DIR}/scan"
    "${SRC_DIR}/settings"
    "${SRC_DIR}/database"
)


if(NOT EXISTS "${MAIN_QML}")
    message(FATAL_ERROR
        "Main.qml was not found: ${MAIN_QML}"
    )
endif()

set_source_files_properties(
    "${MAIN_QML}"
    PROPERTIES
        QT_RESOURCE_ALIAS "Main.qml"
)

qt_add_qml_module(BladeAntivirus
    URI BladeAntivirus
    VERSION 1.0

    QML_FILES
        "${MAIN_QML}"
)

target_link_libraries(BladeAntivirus PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
    Qt6::Network

    bcrypt
    winhttp
    wintrust
    comdlg32
    crypt32
)

set_target_properties(BladeAntivirus PROPERTIES
    WIN32_EXECUTABLE TRUE
    OUTPUT_NAME "BladeAntivirus"
)
