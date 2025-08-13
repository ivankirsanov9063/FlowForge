add_executable(Client
        Client.cpp
        Network.hpp
        ${CMAKE_SOURCE_DIR}/TUN.cpp)

target_compile_features(Client PRIVATE cxx_std_23)

target_include_directories(Client PRIVATE ${CMAKE_SOURCE_DIR})

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL3 REQUIRED libnl-3.0 libnl-route-3.0)
target_include_directories(Client PRIVATE ${LIBNL3_INCLUDE_DIRS})
target_link_libraries(Client PRIVATE ${LIBNL3_LIBRARIES})

install(TARGETS Client RUNTIME DESTINATION bin)
