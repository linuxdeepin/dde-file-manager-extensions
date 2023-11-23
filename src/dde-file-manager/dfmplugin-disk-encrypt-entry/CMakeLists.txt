cmake_minimum_required(VERSION 3.0)

project(dfmplugin_disk_encrypt LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5 REQUIRED COMPONENTS Core Widgets Concurrent)

find_package(Dtk COMPONENTS Widget Core REQUIRED)
find_package(dfm-framework REQUIRED)
find_package(dfm-base REQUIRED)
find_package(dfm-mount REQUIRED)
find_package(dfm-io REQUIRED)

file(GLOB_RECURSE SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
)

add_library(${PROJECT_NAME} SHARED
  ${SRC}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Qt5::Core
    Qt5::Widgets
    Qt5::Concurrent
    ${DtkWidget_LIBRARIES}
    ${DtkCore_LIBRARIES}
    ${dfm-framework_LIBRARIES}
    ${dfm-base_LIBRARIES}
    ${dfm-mount_LIBRARIES}
    ${dfm-io_LIBRARIES}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}
    ${DtkWidget_INCLUDE_DIRS}
    ${DtkCore_INCLUDE_DIRS}
    ${dfm-framework_INCLUDE_DIRS}
    ${dfm-base_INCLUDE_DIRS}
    ${dfm-io_INCLUDE_DIRS}
    ${dfm-mount_INCLUDE_DIRS}
)

target_compile_definitions(${PROJECT_NAME} PRIVATE DFMPLUGIN_DISK_ENCRYPT_LIBRARY)
set_target_properties(${PROJECT_NAME} PROPERTIES LIBRARY_OUTPUT_DIRECTORY ../../)

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${DFM_PLUGIN_FILEMANAGER_EDGE_DIR})
message(">>>> install ${PROJECT_NAME} into ${DFM_PLUGIN_FILEMANAGER_EDGE_DIR}")

dconfig_meta_files(APPID "org.deepin.dde.file-manager"
    BASE "${CMAKE_SOURCE_DIR}/assets/configs"
    FILES "${CMAKE_SOURCE_DIR}/assets/configs/org.deepin.dde.file-manager.diskencrypt.json"
)

execute_process(
    COMMAND lupdate
        ./
        -ts
        -no-obsolete
        ${CMAKE_SOURCE_DIR}/translations/disk-encrypt.ts
    COMMAND lupdate
        ./
        -ts
        -no-obsolete
        ${CMAKE_SOURCE_DIR}/translations/disk-encrypt_zh_CN.ts

    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}
)

execute_process(
    COMMAND lrelease
        ${CMAKE_SOURCE_DIR}/translations/disk-encrypt.ts
    COMMAND lrelease
        ${CMAKE_SOURCE_DIR}/translations/disk-encrypt_zh_CN.ts

    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/translations
    DESTINATION share/dde-file-manager
    FILES_MATCHING PATTERN "*.qm")

