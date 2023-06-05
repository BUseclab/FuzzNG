#include <stdlib.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>

#include "driver.h"
#include "conveyor.h"

extern size_t ignore_addr;
extern size_t ignore_addr_end;
extern size_t min_addr;
extern size_t max_addr;
extern int bloated;

extern uint64_t *kcov_data;
extern size_t kcov_size;

static void *user_access_worker(void* opaque){
    int fd = *(int*)opaque;
    while(!bloated);
    printf(".bloated\n");
    for (;;) {
        debug_printf("polling over %d\n", fd);
        struct pollfd pollfd;
        int nready;
        pollfd.fd = fd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1){
            printf("%s\n","poll\n");
        _Exit(1);
        }

        struct cfu_details details = driver_get_cfu_details();
        debug_printf("CFU: %p +%lx\n", details.addr, details.len);
        if((size_t)details.addr >= min_addr && (size_t)details.addr + details.len <= max_addr &&
				!( (size_t)details.addr <= (size_t)kcov_data + kcov_size && (size_t)kcov_data <= (size_t)details.addr + details.len)){
            ignore_addr = (size_t)details.addr;
            ignore_addr_end = (size_t)details.addr + details.len;

            
            pattern p;
            int min;
            if(details.len>4096) {
                abort_input();
            }
            if(details.string) {
                p.len = details.len;
                min = 4;
            } else if(details.len > 200) {
                abort_input();
                p.len = 200;
                min = 4;
            } else {
                p.len = details.len;
                min = -1;
            }
            if(!ic_advance_until_token(SEPARATOR, 4))
                ic_insert(SEPARATOR, 4, ic_get_cursor());

            p.data = ic_ingest_buf(&p.len, SEPARATOR, 4, min, details.string);
            p.index = 0;
            p.stride = 0;

            if(DEBUG){
                printf(">>> WRITE (%lx) %p %lx \n", kcov_get_current(), details.addr, details.len);
                for(int i=0; i<p.len; i++) {
                    printf("%02x", p.data[i]);
                    if(i%30 == 29)
                        printf("\n");
                }
                printf("\n");
            }
            pattern_alloc(details.addr, details.len, p);
            ignore_addr = 0;
            ignore_addr_end = 0;
        }
        driver_complete_cfu();
    }
}

int cfufd;
void cfu_worker_start(int fd) {
    pthread_t thr;
    cfufd = fd;
    int s = pthread_create(&thr, NULL, user_access_worker, &fd);
    printf(".cfu.sleeping\n");
    sleep(1);
    printf(".cfu.sleeped\n");
    if (s != 0) {
        printf("pthread_create\n");
        _Exit(1);
    }
}
