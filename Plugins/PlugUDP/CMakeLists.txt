cmake_minimum_required(VERSION 3.18)
project(PlugUDP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(PlugUDP SHARED PlugUDP.cpp)

target_include_directories(PlugUDP PUBLIC ${CMAKE_SOURCE_DIR})

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    find_package(Boost 1.70 REQUIRED COMPONENTS system)
    target_include_directories(PlugUDP PUBLIC ${Boost_INCLUDE_DIRS})
    target_link_libraries(PlugUDP PRIVATE Boost::system)
endif()

set_target_properties(PlugUDP PROPERTIES OUTPUT_NAME PlugUDP)
