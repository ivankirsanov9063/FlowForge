add_executable(Client
        ${CMAKE_SYSTEM_NAME}/Client.cpp
        ${CMAKE_SYSTEM_NAME}/Network.cpp
        ${CMAKE_SYSTEM_NAME}/FirewallRules.cpp
        ${CMAKE_SYSTEM_NAME}/NetWatcher.cpp
        ${CMAKE_SYSTEM_NAME}/DNS.cpp
        ${CMAKE_SYSTEM_NAME}/NetworkRollback.cpp

        ${CMAKE_SOURCE_DIR}/PluginWrapper.cpp
        ${CMAKE_SOURCE_DIR}/TUN.cpp
        ${CMAKE_SOURCE_DIR}/Logger.cpp
)

target_compile_definitions(Client PRIVATE _WIN32_WINNT=0x0602 BOOST_USE_WINAPI_VERSION=0x0602)

target_compile_features(Client PRIVATE cxx_std_23)

target_include_directories(Client PRIVATE ${CMAKE_SOURCE_DIR})

find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem)
target_link_libraries(Client PUBLIC Boost::log Boost::log_setup Boost::thread Boost::filesystem)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBNL3 REQUIRED libnl-3.0 libnl-route-3.0)
    target_include_directories(Client PRIVATE ${LIBNL3_INCLUDE_DIRS})
    target_link_libraries(Client PRIVATE ${LIBNL3_LIBRARIES})
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(Client PRIVATE Ws2_32 Iphlpapi)
endif()

install(TARGETS Client RUNTIME DESTINATION bin)
