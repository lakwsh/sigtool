#include <stdlib.h>
#include <string.h>
#ifdef WIN32
#include <windows.h>
#else
#include <sys/mman.h> /* PROT */
#include <unistd.h>   /* sysconf */
#endif
#include "sigtool.h"

void read_sig(uintptr_t addr, mem_sig_t *new_sign, mem_sig_t *&org_sign)
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

void write_sig(uintptr_t addr, mem_sig_t *sign)
{
    CHK_RET(!addr || !sign);

    auto src = (void *)sign->sig;
    auto dst = (void *)(addr + sign->off);

#ifdef WIN32
    DWORD old;
    VirtualProtect(dst, sign->len, PAGE_EXECUTE_READWRITE, &old);
#else
    auto pa_addr = (void *)((uintptr_t)dst & ~(sysconf(_SC_PAGESIZE) - 1));
    size_t size = (uintptr_t)dst - (uintptr_t)pa_addr + sign->len;
    mlock(pa_addr, size);
    mprotect(pa_addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
#endif

    (void)memcpy(dst, src, sign->len);

#ifdef WIN32
    VirtualProtect(dst, sign->len, old, &old);
#else
    //mprotect(pa_addr, size, PROT_READ | PROT_EXEC); /* restore */
    munlock(pa_addr, size);
#endif
}

void free_sig(uintptr_t addr, mem_sig_t *&sign)
{
    write_sig(addr, sign);
    free((void *)sign);
    sign = NULL;
}
