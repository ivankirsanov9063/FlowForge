cmake_minimum_required(VERSION 3.18)
project(PlugUDP LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Boost 1.70 REQUIRED COMPONENTS system)

add_library(PlugUDP SHARED PlugUDP.cpp)

# Ваши общие инклуды проекта
target_include_directories(PlugUDP PUBLIC ${CMAKE_SOURCE_DIR} ${Boost_INCLUDE_DIRS})

# Общие дефайны (при желании)
target_compile_definitions(PlugUDP PRIVATE BOOST_ASIO_NO_DEPRECATED)

# Линковка, общая для всех ОС
target_link_libraries(PlugUDP PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Boost::system
        Threads::Threads
)

# Платформенные отличия
if (WIN32)
    # Сокеты и крипто-API Windows, требуются OpenSSL/Asio
    target_link_libraries(PlugUDP PRIVATE ws2_32 Crypt32 Bcrypt)
else()
    # На Linux/macOS — провал линковки при неопределённых символах
    target_link_options(PlugUDP PRIVATE
            "-Wl,--no-undefined"
            "-Wl,-z,defs"
    )
endif()

set_target_properties(PlugUDP PROPERTIES OUTPUT_NAME PlugUDP)
