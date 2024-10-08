cmake_minimum_required(VERSION 3.10)

project(filemanager-plugins)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Wl,--as-needed")

find_package(DtkCMake REQUIRED)

#安全加固
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-all -Werror=return-type")
if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "mips")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -z noexecstack -z relro")
    add_definitions(-D ARCH_MIPSEL)
endif()

#if no debug, can't out in code define key '__FUNCTION__' and so on
add_definitions(-DQT_MESSAGELOGCONTEXT)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX /usr)
endif()

include(GNUInstallDirs)

# dbus xml dir
set(DFM_DBUS_XML_DIR ${CMAKE_SOURCE_DIR}/assets/dbus)

# defines plugins install dir
if(NOT DEFINED LIB_INSTALL_DIR)
    set(LIB_INSTALL_DIR ${CMAKE_INSTALL_FULL_LIBDIR})
endif()

# root plguins dir
if(NOT DEFINED DFM_PLUGIN_DIR)
    set(DFM_PLUGIN_DIR ${LIB_INSTALL_DIR}/dde-file-manager/plugins)
endif()

# build plugins dir
if(NOT DEFINED DFM_BUILD_PLUGIN_DIR)
    set(DFM_BUILD_PLUGIN_DIR ${CMAKE_CURRENT_BINARY_DIR}/src/plugins)
endif()
add_definitions(-DPLUGIN_DIR="${DFM_BUILD_PLUGIN_DIR}")

# common-core plugins dir
if(NOT DEFINED DFM_PLUGIN_COMMON_CORE_DIR)
    set(DFM_PLUGIN_COMMON_CORE_DIR ${DFM_PLUGIN_DIR}/common-core)
endif()

# desktop-core plugins dir
if(NOT DEFINED DFM_PLUGIN_DESKTOP_CORE_DIR)
    set(DFM_PLUGIN_DESKTOP_CORE_DIR ${DFM_PLUGIN_DIR}/desktop-core)
endif()

# filemanager-core plugins dir
if(NOT DEFINED DFM_PLUGIN_FILEMANAGER_CORE_DIR)
    set(DFM_PLUGIN_FILEMANAGER_CORE_DIR ${DFM_PLUGIN_DIR}/filemanager-core)
endif()

# common-edge plugins dir
if(NOT DEFINED DFM_PLUGIN_COMMON_EDGE_DIR)
    set(DFM_PLUGIN_COMMON_EDGE_DIR ${DFM_PLUGIN_DIR}/common-edge)
endif()

# daemon-edge plugins dir
if(NOT DEFINED DFM_PLUGIN_DAEMON_EDGE_DIR)
    set(DFM_PLUGIN_DAEMON_EDGE_DIR ${DFM_PLUGIN_DIR}/daemon-edge)
endif()

# server-edge plugins dir
if(NOT DEFINED DFM_PLUGIN_SERVER_EDGE_DIR)
    set(DFM_PLUGIN_SERVER_EDGE_DIR ${DFM_PLUGIN_DIR}/server-edge)
endif()

# desktop-edge plugins dir
if(NOT DEFINED DFM_PLUGIN_DESKTOP_EDGE_DIR)
    set(DFM_PLUGIN_DESKTOP_EDGE_DIR ${DFM_PLUGIN_DIR}/desktop-edge)
endif()

# filemanager-edge plugins dir
if(NOT DEFINED DFM_PLUGIN_FILEMANAGER_EDGE_DIR)
    set(DFM_PLUGIN_FILEMANAGER_EDGE_DIR ${DFM_PLUGIN_DIR}/filemanager-edge)
endif()

# tools
if(NOT DEFINED DFM_TOOLS_DIR)
    set(DFM_TOOLS_DIR ${LIB_INSTALL_DIR}/dde-file-manager/tools)
endif()

# dde-file-thumbnail-tool
if(NOT DEFINED DFM_THUMBNAIL_TOOL)
    set(DFM_THUMBNAIL_TOOL ${LIB_INSTALL_DIR}/dde-file-manager/tools)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
      "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif(NOT CMAKE_BUILD_TYPE)
message("Build type:"${CMAKE_BUILD_TYPE})

#Indentify the version
if (${DEEPIN_OS_VERSION} MATCHES "^(23|25)$")
    add_definitions(-DCOMPILE_ON_V23)
    set(COMPLIE_ON_V23 TRUE)
    message("COMPILE ON v2X")
else()
    add_definitions(-DCOMPILE_ON_V20)
    set(COMPLIE_ON_V20 TRUE)
    message("COMPILE ON v20")
endif()

option(OPT_ENABLE_OLDENCRYPTPLUGIN OFF)

add_subdirectory(src)

