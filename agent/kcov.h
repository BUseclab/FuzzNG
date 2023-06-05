#ifndef KCOV_H
#define KCOV_H

#include <net/ethernet.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz.h"

#define KCOV_COVER_SIZE (256 << 11)
#define KCOV_TRACE_PC 0
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64_t)
#define KCOV_REMOTE_ENABLE          _IOW('c', 102, struct kcov_remote_arg)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

#define KCOV_WORDS_PER_CMP 4

#define KCOV_TRACE_PC  0
#define KCOV_TRACE_CMP 1


#define KCOV_SUBSYSTEM_COMMON       (0x00ull << 56)
#define KCOV_SUBSYSTEM_USB  (0x01ull << 56)

#define KCOV_SUBSYSTEM_MASK (0xffull << 56)
#define KCOV_INSTANCE_MASK  (0xffffffffull)

#define KCOV_COMMON_ID      42
#define KCOV_USB_BUS_NUM    1

struct kcov_remote_arg {
    __u32           trace_mode;
    __u32           area_size;
    __u32           num_handles;
    __aligned_u64   common_handle;
    __aligned_u64   handles[0];
};

static inline __u64 kcov_remote_handle(__u64 subsys, __u64 inst)
{
    if (subsys & ~KCOV_SUBSYSTEM_MASK || inst & ~KCOV_INSTANCE_MASK)
            return 0;
    return subsys | inst;
}

#define KCOV_CMP_CONST          (1 << 0)
#define KCOV_CMP_SIZE(n)        ((n) << 1)
#define KCOV_CMP_MASK           KCOV_CMP_SIZE(3)

void kcov_init(void);
void kcov_trace_pc(void);
void kcov_trace_cmp(void);

void kcov_sync_coverage(void);
void kcov_reset_coverage(void);
void kcov_check_coverage(void);
void set_mode(int trace_pc);

uint64_t kcov_get_current(void);

#endif 
