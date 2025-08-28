cmake_minimum_required(VERSION 3.18)
project(PlugDTLS LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(PlugDTLS SHARED
        PlugDTLS.cpp
        ${CMAKE_SOURCE_DIR}/Core/Plugins/Vip.cpp
        ${CMAKE_SOURCE_DIR}/Core/Plugins/VipSession.cpp
)

target_include_directories(PlugDTLS PUBLIC ${CMAKE_SOURCE_DIR})

# ---------------- mbedTLS discovery ----------------
# 1) CMake config package (preferred)
find_package(MbedTLS CONFIG QUIET)

set(_mbedtls_link_done OFF)

if (MbedTLS_FOUND)
    # Targets exported как MbedTLS::mbedtls / ::mbedx509 / ::mbedcrypto
    target_link_libraries(PlugDTLS PRIVATE
            MbedTLS::mbedtls
            MbedTLS::mbedx509
            MbedTLS::mbedcrypto
    )
    set(_mbedtls_link_done ON)
else()
    # 2) pkg-config (Debian/Ubuntu обычно так)
    find_package(PkgConfig QUIET)
    if (PkgConfig_FOUND)
        pkg_check_modules(MBEDTLS QUIET mbedtls mbedx509 mbedcrypto)
    endif()

    if (MBEDTLS_FOUND)
        target_include_directories(PlugDTLS PRIVATE ${MBEDTLS_INCLUDE_DIRS})
        target_link_libraries(PlugDTLS PRIVATE ${MBEDTLS_LIBRARIES})
        set(_mbedtls_link_done ON)
    else()
        # 3) Ручной поиск либ/инклудов
        find_library(LIB_MBEDTLS   NAMES mbedtls)
        find_library(LIB_MBEDX509  NAMES mbedx509)
        find_library(LIB_MBEDCRYPTO NAMES mbedcrypto)
        find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/ssl.h)

        if (LIB_MBEDTLS AND LIB_MBEDX509 AND LIB_MBEDCRYPTO AND MBEDTLS_INCLUDE_DIR)
            target_include_directories(PlugDTLS PRIVATE ${MBEDTLS_INCLUDE_DIR})
            target_link_libraries(PlugDTLS PRIVATE ${LIB_MBEDTLS} ${LIB_MBEDX509} ${LIB_MBEDCRYPTO})
            set(_mbedtls_link_done ON)
        endif()
    endif()
endif()

# 4) Fallback: подтянуть mbedTLS исходниками, если всё выше не сработало
if (NOT _mbedtls_link_done)
    message(STATUS "mbedTLS not found system-wide; fetching source (LTS)")
    include(FetchContent)
    FetchContent_Declare(mbedtls
            GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
            GIT_TAG v2.28.7   # LTS ветка 2.x; стабильные имена таргетов: mbedtls/mbedx509/mbedcrypto
    )
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(mbedtls)

    if (TARGET mbedtls AND TARGET mbedx509 AND TARGET mbedcrypto)
        target_link_libraries(PlugDTLS PRIVATE mbedtls mbedx509 mbedcrypto)
        target_include_directories(PlugDTLS PRIVATE ${mbedtls_SOURCE_DIR}/include)
        set(_mbedtls_link_done ON)
    elseif (TARGET MbedTLS::mbedtls)
        target_link_libraries(PlugDTLS PRIVATE MbedTLS::mbedtls MbedTLS::mbedx509 MbedTLS::mbedcrypto)
        set(_mbedtls_link_done ON)
    else()
        message(FATAL_ERROR "Fetched mbedTLS but no known targets were exported.")
    endif()
endif()

# Windows UDP sockets
if (WIN32)
    target_link_libraries(PlugDTLS PRIVATE ws2_32)
endif()

# Требуем разрешение всех символов при линковке (не применимо к MSVC)
if (NOT WIN32)
    target_link_options(PlugDTLS PRIVATE -Wl,-z,defs)
endif()

set_target_properties(PlugDTLS PROPERTIES OUTPUT_NAME PlugDTLS)
