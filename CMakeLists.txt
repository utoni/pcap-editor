cmake_minimum_required(VERSION 3.5)

project(pcap-editor VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CPACK_PACKAGE_CONTACT "toni@impl.cc")
set(CPACK_DEBIAN_PACKAGE_NAME "pcap-editor")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

include(ExternalProject)
include(CPack)

find_package(QT NAMES Qt6 REQUIRED COMPONENTS Core Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Widgets)
find_library(PCAP_LIBRARY NAMES pcap wpcap)

set_property(SOURCE qhexedit2_init.cpp PROPERTY SKIP_AUTOGEN ON)

qt_add_plugin(qhexedit2
              STATIC
              qhexedit2/src/chunks.cpp
              qhexedit2/src/chunks.h
              qhexedit2/src/commands.cpp
              qhexedit2/src/commands.h
              qhexedit2/src/qhexedit.cpp
              qhexedit2/src/qhexedit.h
              qhexedit2/src/QHexEditPlugin.cpp
              qhexedit2/src/QHexEditPlugin.h
)

ExternalProject_Add(PcapPlusPlus SOURCE_DIR ${CMAKE_SOURCE_DIR}/PcapPlusPlus
                    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/ppp-install
                               -DBUILD_SHARED_LIBS=OFF -DPCAPPP_BUILD_COVERAGE=OFF
                               -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF)

option(ENABLE_SANITIZER "Enable ASAN/LSAN/UBSAN." OFF)
if(ENABLE_SANITIZER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=leak")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment -fsanitize=enum -fsanitize=leak")
endif()

option(ENABLE_THREAD_SANITIZER "Enable TSAN." OFF)
if(ENABLE_THREAD_SANITIZER)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
endif()

if (ENABLE_SANITIZER AND ENABLE_THREAD_SANITIZER)
    message(FATAL_ERROR "ENABLE_SANITIZER and ENABLE_THREAD_SANITIZER must not be enabled at the same time!")
endif()

set(PROJECT_SOURCES
        main.cpp

        mainwindow.cpp
        mainwindow.h
        mainwindow.ui

        bytewindow.cpp
        bytewindow.h
        bytewindow.ui

        pcapplusplus.cpp
        pcapplusplus.h

        qhexedit2/src/chunks.cpp
        qhexedit2/src/chunks.h
        qhexedit2/src/commands.cpp
        qhexedit2/src/commands.h
        qhexedit2/src/qhexedit.cpp
        qhexedit2/src/qhexedit.h
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(pcap-editor
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}
    )
    qt_import_plugins(pcap-editor INCLUDE qhexedit2)
else()
    if(ANDROID)
        add_library(pcap-editor SHARED
            ${PROJECT_SOURCES}
        )
    else()
        add_executable(pcap-editor
            ${PROJECT_SOURCES}
        )
    endif()
endif()

add_dependencies(pcap-editor PcapPlusPlus)

target_include_directories(pcap-editor PRIVATE ${CMAKE_BINARY_DIR}/ppp-install/include/pcapplusplus)
target_link_libraries(pcap-editor PRIVATE Qt${QT_VERSION_MAJOR}::Widgets
                                          ${CMAKE_BINARY_DIR}/ppp-install/lib/libPcap++.a
                                          ${CMAKE_BINARY_DIR}/ppp-install/lib/libPacket++.a
                                          ${CMAKE_BINARY_DIR}/ppp-install/lib/libCommon++.a
                                          ${PCAP_LIBRARY})

set_target_properties(pcap-editor PROPERTIES
    MACOSX_BUNDLE_GUI_IDENTIFIER my.example.com
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

install(TARGETS pcap-editor
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(pcap-editor)
endif()

message(STATUS "QT_DIR: ${QT_DIR}")
