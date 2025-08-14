cmake_minimum_required(VERSION 3.20)

add_library(PlugUDP SHARED
        PlugUDP.cpp
        ${CMAKE_SOURCE_DIR}/Plugin.hpp
)

target_compile_features(PlugUDP PRIVATE cxx_std_23)
target_include_directories(PlugUDP PRIVATE
        ${CMAKE_SOURCE_DIR}        # чтобы видеть Plugin.hpp
)

# --- Boost headers (asio/beast) ---
# Вариант A: через find_package (нужен установленный Boost)
find_package(Boost 1.75 QUIET COMPONENTS headers)
if (Boost_FOUND)
    target_link_libraries(PlugUDP PRIVATE Boost::headers)
    message(STATUS "Using Boost headers from: ${Boost_INCLUDE_DIRS}")
else()
    message(WARNING "Boost headers not found. Install Boost or use vcpkg: "
            "vcpkg install boost-asio boost-beast --triplet x64-windows "
            "и добавь -DCMAKE_TOOLCHAIN_FILE=<vcpkg.cmake>")
endif()

# Со времён Boost 1.70 boost::system — header-only, но на всякий случай:
target_compile_definitions(PlugUDP PRIVATE BOOST_ERROR_CODE_HEADER_ONLY)

if (WIN32)
    target_compile_definitions(PlugUDP PRIVATE
            PLUGUDP_BUILD_DLL
            _WIN32_WINNT=0x0601
            WIN32_LEAN_AND_MEAN
            NOMINMAX
    )
    target_link_libraries(PlugUDP PRIVATE Ws2_32)
    if (MSVC)
        target_compile_options(PlugUDP PRIVATE /W4 /EHsc)
    endif()
else()
    target_compile_definitions(PlugUDP PRIVATE PLUGUDP_BUILD_DLL)
    find_package(Threads)
    if (Threads_FOUND)
        target_link_libraries(PlugUDP PRIVATE Threads::Threads)
    endif()
endif()

# (опционально) выкладываем DLL рядом с Client.exe
add_custom_command(TARGET PlugUDP POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:PlugUDP>
        ${CMAKE_BINARY_DIR}/bin/
)
