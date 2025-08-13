add_executable(Server
        Server.cpp
        Network.cpp
        ${CMAKE_SOURCE_DIR}/TUN.cpp
)

target_compile_features(Server PRIVATE cxx_std_23)

target_include_directories(Server PRIVATE ${CMAKE_SOURCE_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-route-3.0)
pkg_check_modules(NFT REQUIRED libnftables)
target_include_directories(Server PRIVATE ${LIBNL_INCLUDE_DIRS} ${NFT_INCLUDE_DIRS})
target_link_libraries(Server PRIVATE ${LIBNL_LIBRARIES} ${NFT_LIBRARIES})

install(TARGETS Server RUNTIME DESTINATION bin)
