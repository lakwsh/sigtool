#include <stdlib.h>
#include <string.h>
#ifdef _WINDOWS
#include <windows.h>
#else
#include <sys/mman.h> /* PROT */
#include <unistd.h>   /* sysconf */
#endif
#include "sigtool.h"

void read_sig(const uintptr_t addr, const mem_sig_t *new_sign, mem_sig_t *&org_sign)
{
    CHK_RET(!addr || !new_sign);

    org_sign = (mem_sig_t *)malloc(sizeof(mem_sig_t) + new_sign->len);
    CHK_RET(!org_sign);

    org_sign->len = new_sign->len;
    org_sign->off = new_sign->off;

    auto dst = (void *)org_sign->sig;
    auto src = (void *)(addr + new_sign->off);
    (void)memcpy(dst, src, org_sign->len);
}

void write_sig(const uintptr_t addr, const mem_sig_t *sign)
{
    CHK_RET(!addr || !sign);

    auto src = (void *)sign->sig;
    auto dst = (void *)(addr + sign->off);

#ifdef _WINDOWS
    DWORD old;
    VirtualProtect(dst, sign->len, PAGE_EXECUTE_READWRITE, &old);
#else
    auto pg_addr = (void *)((uintptr_t)dst & ~(sysconf(_SC_PAGESIZE) - 1));
    auto size = (size_t)((uintptr_t)dst - (uintptr_t)pg_addr + sign->len);
    mlock(pg_addr, size);
    mprotect(pg_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif

    (void)memcpy(dst, src, sign->len);

#ifdef _WINDOWS
    VirtualProtect(dst, sign->len, old, &old);
#else
    // mprotect(pg_addr, size, PROT_READ | PROT_EXEC); /* restore */
    munlock(pg_addr, size);
#endif
}

void free_sig(const uintptr_t addr, mem_sig_t *&sign)
{
    write_sig(addr, sign);
    free((void *)sign);
    sign = NULL;
}
