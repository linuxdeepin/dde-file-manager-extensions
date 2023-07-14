cmake_minimum_required(VERSION 3.0)

project(dfmplugin_disk_encrypt LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Widgets Concurrent)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Widgets Concurrent)

find_package(Dtk COMPONENTS Widget REQUIRED)
find_package(dfm-framework REQUIRED)
find_package(dfm-base REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_search_module(dfm-io REQUIRED dfm-io IMPORTED_TARGET)

file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

add_library(${PROJECT_NAME} SHARED
  ${SRC}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Widgets
    Qt${QT_VERSION_MAJOR}::Concurrent
    ${DtkWidget_LIBRARIES}
    ${dfm-framework_LIBRARIES}
    ${dfm-base_LIBRARIES}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}
    ${DtkWidget_INCLUDE_DIRS}
    ${dfm-framework_INCLUDE_DIRS}
    ${dfm-base_INCLUDE_DIRS}
    ${dfm-io_INCLUDE_DIRS}
)

target_compile_definitions(${PROJECT_NAME} PRIVATE DFMPLUGIN_DISK_ENCRYPT_LIBRARY)
set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ../../)

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${DFM_PLUGIN_FILEMANAGER_EDGE_DIR})
message(">>>> install ${PROJECT_NAME} into ${DFM_PLUGIN_FILEMANAGER_EDGE_DIR}")
