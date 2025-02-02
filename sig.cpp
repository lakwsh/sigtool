#include <string.h>
#ifdef _WINDOWS
#include <windows.h>
#include <tlhelp32.h>
#else
#include <link.h> /* dl_iterate_phdr */
#include <sys/mman.h>
#endif
#include "sigtool.h"

uintptr_t get_func(const void *addr, const char *func)
{
    CHK_RET_V(!addr || !func, 0);

#ifdef _WINDOWS
    return (uintptr_t)GetProcAddress((HMODULE)addr, func);
#else
    uintptr_t ptr = 0;
    Dl_info info;

    if (dladdr(addr, &info)) {
        void *handle = dlopen(info.dli_fname, RTLD_NOW);
        if (handle) {
            ptr = (uintptr_t)dlsym(handle, func);
            dlclose(handle);
        }
    }
    return ptr;
#endif
}

#ifndef _WINDOWS
static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
    auto d = (mem_info *)data;
    CHK_RET_V(!info->dlpi_name || !strcasestr(info->dlpi_name, d->name), 0); /* path */

    d->addr = (void *)info->dlpi_addr;
    d->len = info->dlpi_phdr[0].p_memsz;
    return 1;
}
#endif

bool find_base(mem_info *info)
{
    CHK_RET_V(!info, false);

    info->addr = NULL;
    info->len = 0;

#ifdef _WINDOWS
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    CHK_RET_V(hModuleSnap == INVALID_HANDLE_VALUE, false);

    bool succ = false;
    MODULEENTRY32 me32 = {sizeof(MODULEENTRY32)}; /* dwSize */
    while (Module32Next(hModuleSnap, &me32)) {    /* srcds */
        if (!_stricmp((char *)me32.szModule, info->name)) {
            info->addr = (void *)me32.modBaseAddr;
            info->len = (size_t)me32.modBaseSize;
            succ = true;
            break;
        }
    }

    CloseHandle(hModuleSnap);
    return succ;
#else
    return dl_iterate_phdr(callback, (void *)info) == 1;
#endif
}

uintptr_t find_sig(const mem_info *base, const mem_sig_t *sign, bool pure)
{
    CHK_RET_V(!base || !sign || !base->addr, 0);

#ifndef _WINDOWS
    mlock(base->addr, base->len);
#endif

    auto p = (uint8_t *)base->addr;
    auto end = p + (base->len - sign->len);

    uintptr_t ret = 0;
    while (p <= end) {
        uint32_t i = 0;
        for (uint8_t *tmp = p; i < sign->len; ++i, ++tmp) {
            uint8_t c = sign->sig[i];
            if (!pure && (c == (uint8_t)'*')) continue;
            if (c != *tmp) break;
        }

        if (i == sign->len) {
            ret = (uintptr_t)p;
            break;
        }

        p++;
    }

#ifndef _WINDOWS
    munlock(base->addr, base->len);
#endif

    return ret;
}
