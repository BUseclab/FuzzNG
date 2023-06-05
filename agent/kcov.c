#include <sys/io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <assert.h>
#include <pthread.h>

#include "kcov.h"
#include "fuzz.h"
#include "device.h"


uint64_t *kcov_data;
size_t kcov_size = KCOV_COVER_SIZE * sizeof(kcov_data[0]);
uint64_t *remote_kcov_data;
static int fd;
int remote_fd;
int mode = KCOV_TRACE_CMP;

void set_mode(int trace_pc){
    if(trace_pc){
        mode = KCOV_TRACE_PC;
    } else {
        mode = KCOV_TRACE_CMP;
    }
    
}

void fail(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	exit(1);
}

void kcov_trace_pc(void){
    if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
        fail("cover enable write trace failed");
    mode = KCOV_TRACE_PC;
}

void kcov_trace_cmp(void){
    if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_CMP)){
        fail("cover enable write trace failed");
    }
    mode = KCOV_TRACE_CMP;
}


int open_kcov_fd(void** data){
    int kcov_fd = open("/sys/kernel/debug/kcov", O_RDWR);
    if (kcov_fd== -1)
        fail("open of /sys/kernel/debug/kcov failed");
    if (ioctl(kcov_fd, KCOV_INIT_TRACE64, KCOV_COVER_SIZE))
        fail("cover init trace write failed");
    *data = (uint64_t*)mmap(NULL, kcov_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, kcov_fd, 0);

    if (*data == MAP_FAILED)
        fail("cover mmap failed");
    return kcov_fd;
}

static uint64_t remote_handle;
void* kcov_remote(void* a){
    int i;
    struct kcov_remote_arg arg = {};
    remote_fd = open_kcov_fd((void**)&remote_kcov_data);

    memset(remote_kcov_data, 0, KCOV_COVER_SIZE * sizeof(kcov_data[0]));
    for(i=0; i < KCOV_COVER_SIZE; i+=0x1000/sizeof(remote_kcov_data[0]))
        outl(virt_to_phys(&remote_kcov_data[i]) ,0x922 + FUZZ_DEVICE_ADD_REMOTE_COV_ARRAY);

    arg.trace_mode = mode;
    arg.area_size = KCOV_COVER_SIZE;
    arg.num_handles = 0;
    arg.common_handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON,
                                                    KCOV_COMMON_ID);
    if (ioctl(remote_fd, KCOV_REMOTE_ENABLE, &arg)){
            perror("ioctl");
            fail("ioctl");
    }
    printf("Pausing Remote Thread...\n");
    while(1)
        pause();
    return NULL;
}

uint64_t kcov_get_current(void) {
    int n = __atomic_load_n(&kcov_data[0], __ATOMIC_RELAXED) -1;
    uint64_t pc;
    if (n<0)
        return -1;
    if(mode == KCOV_TRACE_PC) {
        pc =   __atomic_load_n(&kcov_data[1+n], __ATOMIC_RELAXED);
    } else {
        pc =   __atomic_load_n(&kcov_data[1+(n*4)+3], __ATOMIC_RELAXED);
    }
    return pc;
}

void kcov_print_data(void){
    printf("KCOV Data:\n");
    for(int i=0; i<4096; i++){
        printf("%02x", ((uint8_t*)kcov_data)[i]);
        if(i%20 ==19)
            printf("\n");
    }
}

void kcov_init(void){
    int i;
    pthread_t kcov_remote_thread;

    pthread_create(&kcov_remote_thread, NULL, kcov_remote, NULL);
    fd = open_kcov_fd((void**)&kcov_data);
    memset(kcov_data, 0, KCOV_COVER_SIZE * sizeof(kcov_data[0]));
    for(i=0; i < KCOV_COVER_SIZE; i+=0x1000/sizeof(kcov_data[0]))
        outl(virt_to_phys(&kcov_data[i]) ,0x922 + FUZZ_DEVICE_ADD_CMP_ARRAY);
}

int kcov_dead(void)
{
    return !(fcntl(fd, F_GETFD) != -1 || errno != EBADF);
}

static void kcov_reset_bitmap(uint64_t* data){
    __atomic_store_n(&data[0], 0 , __ATOMIC_RELAXED);
}

void kcov_reset_coverage(void){
    if(kcov_data)
        kcov_reset_bitmap(kcov_data);
    if(remote_kcov_data)
        kcov_reset_bitmap(remote_kcov_data);
}

