cmake_minimum_required(VERSION 3.18)

project(ClientCore LANGUAGES CXX)

# Выравниваем ABI Boost под системные .so (в т.ч. libboost_log.so)
add_compile_definitions(BOOST_ALL_DYN_LINK)

add_library(ClientCore SHARED
        ${CMAKE_SYSTEM_NAME}/Client.cpp
        ${CMAKE_SYSTEM_NAME}/Network.cpp
        ${CMAKE_SYSTEM_NAME}/FirewallRules.cpp
        ${CMAKE_SYSTEM_NAME}/NetWatcher.cpp
        ${CMAKE_SYSTEM_NAME}/DNS.cpp
        ${CMAKE_SYSTEM_NAME}/NetworkRollback.cpp

        ${CMAKE_SOURCE_DIR}/Core/PluginWrapper.cpp
        ${CMAKE_SOURCE_DIR}/Core/TUN.cpp
        ${CMAKE_SOURCE_DIR}/Core/Logger.cpp
)

if (WIN32)
    target_compile_definitions(ClientCore PRIVATE _WIN32_WINNT=0x0602 BOOST_USE_WINAPI_VERSION=0x0602)
endif()

target_compile_features(ClientCore PRIVATE cxx_std_23)
target_include_directories(ClientCore PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem regex)
find_package(Threads REQUIRED)

# Важно: log_setup раньше log; добавляем потоки и dl (Linux)
target_link_libraries(ClientCore
        PRIVATE
        Boost::log_setup
        Boost::log
        Boost::thread
        Boost::filesystem
        Boost::regex
        Threads::Threads
)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBNL3 REQUIRED libnl-3.0 libnl-route-3.0)
    pkg_check_modules(LIBNFT REQUIRED libnftables)
    pkg_check_modules(LIBSYSTEMD REQUIRED libsystemd)
    target_compile_definitions(ClientCore PRIVATE HAVE_LIBSYSTEMD=1)
    target_include_directories(ClientCore PRIVATE ${LIBNL3_INCLUDE_DIRS} ${LIBNFT_INCLUDE_DIRS} ${LIBSYSTEMD_INCLUDE_DIRS})
    target_link_libraries(ClientCore PRIVATE ${LIBNL3_LIBRARIES} ${LIBNFT_LIBRARIES} ${LIBSYSTEMD_LIBRARIES} dl)
endif()

if (WIN32)
    target_link_libraries(ClientCore PRIVATE Ws2_32 Iphlpapi)
endif()

install(TARGETS ClientCore RUNTIME DESTINATION bin)
