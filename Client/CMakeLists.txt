add_executable(Client
        Client.cpp
        Network.cpp
        ${CMAKE_SOURCE_DIR}/PluginWrapper.cpp
        ${CMAKE_SOURCE_DIR}/TUN.cpp
)

target_compile_features(Client PRIVATE cxx_std_23)
target_include_directories(Client PRIVATE ${CMAKE_SOURCE_DIR})

if (WIN32)
    # Windows: WinAPI/WSA/IpHelper
    target_compile_definitions(Client PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            _WIN32_WINNT=0x0601  # Win7+ API; можно поднять до 0x0A00 для Win10
    )
    target_link_libraries(Client PRIVATE Iphlpapi Ws2_32)

    # Рекомендуемые флаги для MSVC (необязательно):
    if (MSVC)
        target_compile_options(Client PRIVATE /W4 /permissive- /EHsc)
        # /MP параллельная компиляция
        add_compile_options(/MP)
    endif()
else() # Linux/Unix
    find_package(PkgConfig REQUIRED)
    # Удобнее через IMPORTED_TARGET, чтобы не тащить вручную include/lib dirs
    pkg_check_modules(LIBNL3 REQUIRED IMPORTED_TARGET libnl-3.0 libnl-route-3.0)

    target_link_libraries(Client PRIVATE PkgConfig::LIBNL3 dl)

    # (опционально) если где-то используешь std::thread:
    find_package(Threads)
    if (Threads_FOUND)
        target_link_libraries(Client PRIVATE Threads::Threads)
    endif()

    # Рекомендуемые варнинги для GCC/Clang (необязательно):
    if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(Client PRIVATE
                -Wall -Wextra -Wpedantic
                -Wconversion -Wsign-conversion -Wshadow -Wformat=2
        )
    endif()
endif()

install(TARGETS Client RUNTIME DESTINATION bin)
