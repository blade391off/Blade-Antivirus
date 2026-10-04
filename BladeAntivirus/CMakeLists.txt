cmake_minimum_required(VERSION 3.20)

project(BladeAntivirus VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(BladeAntivirus WIN32
    src/main.cpp
    src/scanner/scanner.cpp
    src/scanner/hash_detector.cpp
    src/updater/updater.cpp
    src/signs/signs.cpp
)

target_include_directories(BladeAntivirus PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/scanner
    ${CMAKE_CURRENT_SOURCE_DIR}/src/updater
    ${CMAKE_CURRENT_SOURCE_DIR}/src/signs
)

if(WIN32)
    target_link_libraries(BladeAntivirus PRIVATE
        bcrypt
        winhttp
        comdlg32
    )
endif()

if(MSVC)
    target_compile_options(BladeAntivirus PRIVATE
        /W4
        /permissive-
    )
endif()