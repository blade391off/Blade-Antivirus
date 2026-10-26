
cmake_minimum_required(VERSION 3.21)

project(BladeAntivirus
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_PREFIX_PATH "D:/Qt/6.12.0/mingw_64" CACHE PATH "Qt CMake path" FORCE)

find_package(Qt6 REQUIRED COMPONENTS
    Quick
    Qml
    Widgets
)

qt_standard_project_setup()

qt_add_executable(BladeAntivirus WIN32
    src/appicon.rc

    src/main.cpp

    src/app/antiviruscontroller.cpp
    src/app/antiviruscontroller.h

    src/scanner/scanner.cpp
    src/scanner/scanner.h
    src/scanner/hash_detector.cpp

    src/updater/updater.cpp
    src/updater/updater.h

    src/signs/signs.cpp
    src/signs/signs.hpp

    src/heuristic/heuristic_detector.h
    src/heuristic/heuristic_detector.cpp

    src/behavior/behavior_monitor.h
    src/behavior/behavior_monitor.cpp

    src/realtime/realtime_protection.h
    src/realtime/realtime_protection.cpp

    src/scan/scan_controller.h
    src/scan/scan_controller.cpp

    src/settings/app_settings.h
    src/settings/app_settings.cpp
)

qt_add_qml_module(BladeAntivirus
    URI BladeAntivirus
    VERSION 1.0
    QML_FILES
        src/qml/Main.qml
)

target_include_directories(BladeAntivirus PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/app"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/scanner"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/updater"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/signs"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/heuristic"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/behavior"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/realtime"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/scan"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/settings"
)

target_compile_definitions(BladeAntivirus PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(BladeAntivirus PRIVATE
    Qt6::Quick
    Qt6::Qml
    Qt6::Widgets
    bcrypt
    winhttp
    advapi32
)

if(MSVC)
    target_compile_options(BladeAntivirus PRIVATE /W4 /permissive-)
elseif(MINGW)
    target_compile_options(BladeAntivirus PRIVATE -Wall -Wextra)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/database/hashes.txt")
    add_custom_command(TARGET BladeAntivirus POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:BladeAntivirus>/database"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/database/hashes.txt"
            "$<TARGET_FILE_DIR:BladeAntivirus>/database/hashes.txt"
        VERBATIM
    )
endif()
