#include <stdio.h>
#include <inttypes.h>
#include "sigtool.h"

int main(void)
{
#ifdef WIN32
    mem_info info = {.name = "kernel32.dll"};
#else
    mem_info info = {.name = "libc.so"};
#endif
    printf("[find_base] ret=%d ", find_base(&info));
    printf("base=%p len=0x%" PRIxPTR "\n", info.addr, info.len);

#ifdef WIN32
    printf("[get_func] ret=0x%" PRIxPTR "\n", get_func(info.addr, "GetProcAddress"));
#else
    printf("[get_func] ret=0x%" PRIxPTR "\n", get_func(info.addr, "printf"));
#endif

#ifdef WIN32
    uint8_t sig[] = "\x02\x00\x4D\x5A"; /* MZ */
#else
    uint8_t sig[] = "\x03\x00\x45\x4C\x46"; /* ELF */
#endif
    printf("[find_sig] ret=0x%" PRIxPTR "\n", find_sig(&info, (mem_sig_t *)&sig, true));

#ifndef WIN32
    mem_info self = {.name = ""};
    find_base(&self);
    printf("[get_sym] ret=0x%" PRIxPTR "\n", get_sym(self.addr, "main"));
#endif

    mem_sig_t *org;
    uint8_t patch[] = "\x06\x01lakwsh";
    read_sig((uintptr_t)info.addr, (mem_sig_t *)&patch, org);
    printf("[read_sig] org=%p len=%u off=%d val=[", org, org->len, org->off);
    for (uint8_t i = 0; i < patch[0]; i++) printf("%X ", org->sig[i]);
    printf("\b]\n");

    write_sig((uintptr_t)info.addr, (mem_sig_t *)&patch);
    printf("[write_sig] val=[");
    for (uint8_t i = 0; i < patch[0]; i++) printf("%X ", ((uint8_t *)info.addr)[i]);
    printf("\b]\n");

    free_sig((uintptr_t)info.addr, org);
    printf("[free_sig] org=%p val=[", org);
    for (uint8_t i = 0; i < patch[0]; i++) printf("%X ", ((uint8_t *)info.addr)[i]);
    printf("\b]\n");

    return 0;
}
