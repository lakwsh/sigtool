#ifndef _WINDOWS
#include <dlfcn.h> /* dladdr */
#include <elf.h>
#include <fcntl.h> /* open */
#include <string.h>
#include <sys/mman.h>
#include <unistd.h> /* lseek */
#endif
#include "sigtool.h"

uintptr_t get_sym(const void *base, const char *symbol)
{
    CHK_RET_V(!base || !symbol, 0);

#ifdef _WINDOWS
    return 0; /* not supported */
#else
    Dl_info info;
    CHK_RET_V(!dladdr(base, &info), 0);
    int fd = open(info.dli_fname, O_RDONLY);
    CHK_RET_V(fd == -1, 0);

    off_t size = lseek(fd, 0, SEEK_END);
    if (size == -1) {
        close(fd);
        return 0;
    }

    auto addr = (uintptr_t)mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    CHK_RET_V((void *)addr == MAP_FAILED, 0);

    uintptr_t result = 0;
    auto elf_hdr = (Elf32_Ehdr *)addr;
    Elf32_Half st_idx = elf_hdr->e_shstrndx;
    /* sect string table missing */
    if (elf_hdr->e_shoff && (st_idx != SHN_UNDEF)) {
        auto sec_hdr = (Elf32_Shdr *)(addr + elf_hdr->e_shoff);
        auto sec_dat = (const char *)(addr + sec_hdr[st_idx].sh_offset);
        Elf32_Shdr *sec_sym = NULL, *sec_str = NULL;
        for (uint32_t i = 0; i < elf_hdr->e_shnum; ++i) {
            auto sec_name = sec_dat + sec_hdr[i].sh_name;
            if (!strcmp(sec_name, ".symtab")) sec_sym = &sec_hdr[i];
            else if (!strcmp(sec_name, ".strtab")) sec_str = &sec_hdr[i];
        }

        if (sec_sym && sec_str) {
            auto sym = (Elf32_Sym *)(addr + sec_sym->sh_offset);  /* symbol offset */
            auto str = (const char *)(addr + sec_str->sh_offset); /* symbol name */
            for (uint32_t i = 0; i < (sec_sym->sh_size / sec_sym->sh_entsize); ++i) {
                if (!strcmp(symbol, str + sym[i].st_name)) {
                    result = (uintptr_t)base + sym[i].st_value;
                    break;
                }
            }
        }
    }

    (void)munmap((void *)addr, (size_t)size);
    return result;
#endif
}
