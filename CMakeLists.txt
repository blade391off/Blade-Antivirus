
cmake_minimum_required(VERSION 3.25)

project(BladeAntivirus VERSION 1.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_AUTOMOC ON)

set(PROJECT_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(SRC_DIR "${PROJECT_ROOT}/src")
set(MAIN_QML "${SRC_DIR}/qml/Main.qml")

set_source_files_properties("${MAIN_QML}" PROPERTIES
    QT_RESOURCE_ALIAS "Main.qml"
)

# Toolchain paths are overridable, so the checkout also builds where YARA or
# OpenSSL live somewhere else:
#   cmake -S . -B build -DYARA_ROOT=C:/tools/yara -DOPENSSL_CRYPTO=C:/tools/libcrypto.a
set(YARA_ROOT "D:/yara/install" CACHE PATH
    "YARA 4.5 installation prefix (include/yara.h, lib/liblibyara.a)")
set(OPENSSL_CRYPTO "D:/yara/installed/x64-mingw-dynamic-static/lib/libcrypto.a"
    CACHE FILEPATH "Static OpenSSL libcrypto library required by YARA")
set(YARA_LIBRARY "${YARA_ROOT}/lib/liblibyara.a")

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

file(GLOB_RECURSE BLADE_SOURCES CONFIGURE_DEPENDS
    "${SRC_DIR}/*.cpp"
)

file(GLOB_RECURSE BLADE_HEADERS CONFIGURE_DEPENDS
    "${SRC_DIR}/*.h"
    "${SRC_DIR}/*.hpp"
)

set(WINDOWS_RESOURCES
    "${SRC_DIR}/appicon.rc"
)

if(NOT EXISTS "${YARA_ROOT}/include/yara.h")
    message(FATAL_ERROR "YARA headers not found")
endif()

if(NOT EXISTS "${YARA_LIBRARY}")
    message(FATAL_ERROR "YARA library not found")
endif()

if(NOT EXISTS "${OPENSSL_CRYPTO}")
    message(FATAL_ERROR "OpenSSL Crypto library not found")
endif()

qt_add_executable(BladeAntivirus WIN32
    ${BLADE_SOURCES}
    ${BLADE_HEADERS}
    ${WINDOWS_RESOURCES}
)

qt_add_qml_module(BladeAntivirus
    URI BladeAntivirus
    VERSION 1.0
    QML_FILES
        "${MAIN_QML}"
)

target_include_directories(BladeAntivirus PRIVATE
    "${SRC_DIR}"
    "${YARA_ROOT}/include"
)

target_link_libraries(BladeAntivirus PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Qml
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::Widgets
    Qt6::Network
    "${YARA_LIBRARY}"
    "${OPENSSL_CRYPTO}"
    bcrypt
    winhttp
    wintrust
    comdlg32
    crypt32
    advapi32
    ws2_32
)

target_compile_definitions(BladeAntivirus PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    # Development fallback for the detection database and YARA rules when
    # the app runs straight from a build directory.
    BLADE_SOURCE_DIR="${PROJECT_ROOT}"
    BLADE_VERSION="${PROJECT_VERSION}"
)

# Keep the shipped data next to the executable so a clean machine can scan
# before the first successful update. Without this the only source of
# hashes.txt was the network.
add_custom_command(TARGET BladeAntivirus POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:BladeAntivirus>/database"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${PROJECT_ROOT}/database/hashes.txt"
        "$<TARGET_FILE_DIR:BladeAntivirus>/database/hashes.txt"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${PROJECT_ROOT}/yara"
        "$<TARGET_FILE_DIR:BladeAntivirus>/yara"
    COMMENT "Copying detection database and YARA rules next to the executable"
)

install(TARGETS BladeAntivirus RUNTIME DESTINATION .)
install(DIRECTORY "${PROJECT_ROOT}/database" DESTINATION .)
install(DIRECTORY "${PROJECT_ROOT}/yara" DESTINATION .)

set_target_properties(BladeAntivirus PROPERTIES
    OUTPUT_NAME "BladeAntivirus"
    VERSION ${PROJECT_VERSION}
)

message(STATUS "BladeAntivirus ${PROJECT_VERSION}")
message(STATUS "YARA 4.5.0 configured")
message(STATUS "QML module: BladeAntivirus")
