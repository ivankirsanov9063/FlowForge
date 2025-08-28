add_library(ServerCore SHARED
        ${CMAKE_SYSTEM_NAME}/Server.cpp
        ${CMAKE_SYSTEM_NAME}/Network.cpp
        ${CMAKE_SYSTEM_NAME}/NetworkRollback.cpp
        ${CMAKE_SYSTEM_NAME}/NetWatcher.cpp
        ${CMAKE_SOURCE_DIR}/Core/PluginWrapper.cpp
        ${CMAKE_SOURCE_DIR}/Core/TUN.cpp
        ${CMAKE_SOURCE_DIR}/Core/Logger.cpp
)

target_compile_features(ServerCore PRIVATE cxx_std_23)

target_include_directories(ServerCore PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Boost REQUIRED COMPONENTS log log_setup thread filesystem)
target_link_libraries(ServerCore PUBLIC Boost::log Boost::log_setup Boost::thread Boost::filesystem)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-route-3.0)
    pkg_check_modules(NFT REQUIRED libnftables)
    target_include_directories(ServerCore PRIVATE ${LIBNL_INCLUDE_DIRS} ${NFT_INCLUDE_DIRS})
    target_link_libraries(ServerCore PRIVATE ${LIBNL_LIBRARIES} ${NFT_LIBRARIES})
endif()

install(TARGETS ServerCore RUNTIME DESTINATION bin)
