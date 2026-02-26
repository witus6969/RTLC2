cmake_minimum_required(VERSION 3.16)
project(rtlc2-loaders LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler options
if(MSVC)
    add_compile_options(/W4 /O2 /MT)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -O2)
    if(WIN32)
        add_compile_options(-static -static-libgcc)
    endif()
endif()

# shellcode_data.h is generated in the build directory by the build script
# It must be present before building

if(WIN32)
    # Windows EXE Loader
    add_executable(rtlc2-loader-exe loader_win.c)
    target_include_directories(rtlc2-loader-exe PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(rtlc2-loader-exe PRIVATE kernel32)

    # Windows DLL Loader
    add_library(rtlc2-loader-dll SHARED loader_dll_win.c)
    target_include_directories(rtlc2-loader-dll PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(rtlc2-loader-dll PRIVATE kernel32)
    set_target_properties(rtlc2-loader-dll PROPERTIES PREFIX "" OUTPUT_NAME "rtlc2-loader")
else()
    # POSIX (Linux/macOS) Loader
    add_executable(rtlc2-loader loader_posix.c)
    target_include_directories(rtlc2-loader PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    if(APPLE)
        target_link_libraries(rtlc2-loader PRIVATE "-framework Security")
    else()
        target_link_libraries(rtlc2-loader PRIVATE pthread)
    endif()
endif()

# Strip symbols in release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(NOT MSVC)
        if(WIN32)
            if(TARGET rtlc2-loader-exe)
                add_custom_command(TARGET rtlc2-loader-exe POST_BUILD
                    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:rtlc2-loader-exe> 2>/dev/null || true)
            endif()
            if(TARGET rtlc2-loader-dll)
                add_custom_command(TARGET rtlc2-loader-dll POST_BUILD
                    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:rtlc2-loader-dll> 2>/dev/null || true)
            endif()
        else()
            if(TARGET rtlc2-loader)
                add_custom_command(TARGET rtlc2-loader POST_BUILD
                    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:rtlc2-loader> 2>/dev/null || true)
            endif()
        endif()
    endif()
endif()
