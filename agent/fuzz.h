#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>
#include <stddef.h>

/*
 * SEPARATOR is used to separate "operations" in the fuzz input
 */

#define SEPARATOR (uint8_t*)"FUZZ"
#ifndef DEBUG
#define DEBUG 0
#endif
#define debug_printf(fmt, ...)                                                 \
    do {                                                                       \
        if (DEBUG){                                                             \
            printf(fmt, __VA_ARGS__);                                 \
            fflush(stdout); \
        } \
    } while (0)

typedef struct {
    uint8_t index;      /* Index of a byte to increment by stride */
    uint8_t stride;     /* Increment each index'th byte by this amount */
    size_t len;
    const uint8_t *data;
} pattern;

extern unsigned char libfuzzer_coverage[32 << 10];

size_t virt_to_phys(void* vaddr);

void pattern_alloc(void* ptr, size_t len, pattern p);

extern pattern last_pattern;

void bloatme(void);

void early_exit(void);
void cfu_worker_start(int fd);
void kcov_print_data(void);
void abort_input(void);
uint64_t kcov_get_current(void);

#endif
