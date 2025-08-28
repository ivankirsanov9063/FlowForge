cmake_minimum_required(VERSION 3.18)
project(PlugDTLS LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(PlugDTLS SHARED
        PlugDTLS.cpp
        ${CMAKE_SOURCE_DIR}/Core/Plugins/Vip.cpp
        ${CMAKE_SOURCE_DIR}/Core/Plugins/VipSession.cpp)

target_include_directories(PlugDTLS PUBLIC ${CMAKE_SOURCE_DIR})

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
target_include_directories(PlugDTLS PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(PlugDTLS PRIVATE OpenSSL::SSL OpenSSL::Crypto Boost::system)

target_link_options(PlugDTLS PRIVATE -Wl,-z,defs)

set_target_properties(PlugDTLS PROPERTIES OUTPUT_NAME PlugDTLS)
