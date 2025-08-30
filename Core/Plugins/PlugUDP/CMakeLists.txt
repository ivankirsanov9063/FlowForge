cmake_minimum_required(VERSION 3.18)
project(PlugUDP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)

add_library(PlugUDP SHARED PlugUDP.cpp)

target_include_directories(PlugUDP PUBLIC ${CMAKE_SOURCE_DIR})

if (WIN32)
find_package(Boost 1.70 REQUIRED COMPONENTS system)
target_include_directories(PlugUDP PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(PlugUDP PRIVATE Boost::system Threads::Threads)
else()
find_package(OpenSSL REQUIRED)
find_package(Boost 1.70 REQUIRED COMPONENTS system)
target_include_directories(PlugUDP PUBLIC ${Boost_INCLUDE_DIRS})
target_link_libraries(PlugUDP PRIVATE
OpenSSL::SSL
OpenSSL::Crypto
Boost::system
Threads::Threads
)
# Провал линковки при любых неопределённых символах в .so
target_link_options(PlugUDP PRIVATE
"-Wl,--no-undefined"
"-Wl,-z,defs"
)
endif()

# (опционально, чтобы не тянуть устаревшие API asio)
target_compile_definitions(PlugUDP PRIVATE -DBOOST_ASIO_NO_DEPRECATED)

set_target_properties(PlugUDP PROPERTIES OUTPUT_NAME PlugUDP)