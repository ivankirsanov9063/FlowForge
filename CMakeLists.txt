cmake_minimum_required(VERSION 3.20)

project(FlowForge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
            -Wall -Wextra -Wpedantic
            -Wconversion -Wsign-conversion
            -Wshadow -Wformat=2
    )
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(CMAKE_CONFIGURATION_TYPES)
    foreach(cfg ${CMAKE_CONFIGURATION_TYPES})
        string(TOUPPER "${cfg}" cfgU)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${cfgU} ${CMAKE_BINARY_DIR}/bin)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${cfgU} ${CMAKE_BINARY_DIR}/bin)
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${cfgU} ${CMAKE_BINARY_DIR}/bin)
    endforeach()
endif()

add_subdirectory(Client)
add_subdirectory(Server)
add_subdirectory(Plugins)

set(SH_SCRIPTS
        "${CMAKE_SOURCE_DIR}/Client/client_network.sh"
        "${CMAKE_SOURCE_DIR}/Server/server_network.sh"
)

add_custom_target(copy_scripts ALL
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/bin"
)

foreach(script IN LISTS SH_SCRIPTS)
    get_filename_component(fname "${script}" NAME)
    add_custom_command(TARGET copy_scripts POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${script}" "${CMAKE_BINARY_DIR}/bin/${fname}"
            COMMAND /bin/chmod a+x "${CMAKE_BINARY_DIR}/bin/${fname}"
            VERBATIM
    )
endforeach()
