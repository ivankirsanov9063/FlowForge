add_executable(Server
        ${CMAKE_SYSTEM_NAME}/Server.cpp
        ${CMAKE_SYSTEM_NAME}/Network.cpp
        ${CMAKE_SYSTEM_NAME}/NetworkRollback.cpp
        ${CMAKE_SYSTEM_NAME}/NetWatcher.cpp
        ${CMAKE_SOURCE_DIR}/PluginWrapper.cpp
        ${CMAKE_SOURCE_DIR}/TUN.cpp
        ${CMAKE_SOURCE_DIR}/Logger.cpp
)

target_compile_features(Server PRIVATE cxx_std_23)

target_include_directories(Server PRIVATE ${CMAKE_SOURCE_DIR})

find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem)
target_link_libraries(Server PUBLIC Boost::log Boost::log_setup Boost::thread Boost::filesystem)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-route-3.0)
    pkg_check_modules(NFT REQUIRED libnftables)
    target_include_directories(Server PRIVATE ${LIBNL_INCLUDE_DIRS} ${NFT_INCLUDE_DIRS})
    target_link_libraries(Server PRIVATE ${LIBNL_LIBRARIES} ${NFT_LIBRARIES})
endif()

install(TARGETS Server RUNTIME DESTINATION bin)
