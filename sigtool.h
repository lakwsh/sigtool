#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <stddef.h>
#include <stdint.h>

#define CHK_RET(cond)     \
    do {                  \
        if (cond) return; \
    } while (0);
#define CHK_RET_V(cond, val)  \
    do {                      \
        if (cond) return val; \
    } while (0);

typedef struct {
    const char *name;
    void *addr;
    size_t len;
} mem_info;

typedef struct {
    uint8_t len;
    int8_t off;
    uint8_t sig[];
} mem_sig_t;

uintptr_t get_func(const void *addr, const char *func);
bool find_base(mem_info *info);
uintptr_t find_sig(const mem_info *base, const mem_sig_t *sign, bool pure);

uintptr_t get_sym(const void *base, const char *sym);

bool check_addr(const uintptr_t addr);
void read_sig(const uintptr_t addr, const mem_sig_t *new_sign, mem_sig_t *&org_sign);
void write_sig(const uintptr_t addr, const mem_sig_t *sign);
void free_sig(const uintptr_t addr, mem_sig_t *&sign);

#endif  // SIGNATURE_H
