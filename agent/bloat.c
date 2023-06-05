#define _GNU_SOURCE
#include <inttypes.h>
#include <sys/types.h>
#include <stdio.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <pthread.h>

#include "fuzz.h"
#include "conveyor.h"

int uffd;

size_t ignore_addr;
size_t ignore_addr_end;
size_t min_addr=-1;
size_t max_addr;
int bloated;

static void uffd_setup(void){
    struct uffdio_api uffdio_api;
    int tmpfd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    uffd = dup2(tmpfd, 100);
    close(tmpfd);
    debug_printf("UFFD is %d\n", uffd);
    if(uffd == -1){
        printf("Failed to open UFFD\n");
        exit(1);
    }
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1){
        printf("ioctl-UFFDIO_API\n");
        exit(1);
    }
}

static void uffd_register(size_t start, size_t len, int mode){
    struct uffdio_register uffdio_register;
    uffdio_register.range.start = start;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1){
        printf("ioctl-UFFDIO_REGISTER\n");
        exit(1);
    }

}

static void* uffd_worker(void* param){
    static int fault_cnt;
    static struct uffd_msg msg;   /* Data read from userfaultfd */
    static char *page = NULL;
    struct uffdio_copy uffdio_copy;
    struct uffdio_zeropage uffdio_zeropage;
    size_t nread;

    size_t page_size = 4096;
    if (page == NULL) {
        page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (page == MAP_FAILED){
            printf("mmap\n");
            exit(1);
        }
    }
    sleep(1);
    for (;;) {

        /* See what poll() tells us about the userfaultfd. */

        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);
        if (nready == -1){
            printf("%s\n","poll\n");
            exit(1);
        }

        nread = read(uffd, &msg, sizeof(msg));
        if (nread == 0) {
            printf("%s\n","EOF on userfaultfd!\n");
            exit(1);
        }

        if (nread == -1){
            printf("%s\n","read -1");
            exit(1);
        }

        /* We expect only one kind of event; verify that assumption. */
        if (msg.event != UFFD_EVENT_PAGEFAULT) {
            fprintf(stderr, "Unexpected event on userfaultfd\n");
            exit(1);
        }

        /* Display info about the page-fault event. */

        // Is it a write?
        if(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WRITE) {
            debug_printf("%s","UFFD Write... Skipping\n");
            uffdio_zeropage.range.start = (unsigned long) msg.arg.pagefault.address &
                ~(page_size - 1);
            uffdio_zeropage.range.len = page_size;
            ioctl(uffd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
            continue;
        }

        // Does it match with a CFU cb?
        if(msg.arg.pagefault.address >= (ignore_addr & 0x000) && msg.arg.pagefault.address <= (ignore_addr_end | 0xFFF)){
            debug_printf("%s","IN_CFU... Skipping\n");
            uffdio_zeropage.range.start = (unsigned long) msg.arg.pagefault.address &
                ~(page_size - 1);
            uffdio_zeropage.range.len = page_size;
            ioctl(uffd, UFFDIO_ZEROPAGE, &uffdio_zeropage);
            continue;
        }
        fflush(stdout);

        /* Copy the page pointed to by 'page' into the faulting
           region. Vary the contents that are copied in, so that it
           is more obvious that each fault is handled separately. */
        if(!ic_advance_until_token(SEPARATOR, 4))
            ic_insert(SEPARATOR, 4, ic_get_cursor());
        pattern p;
        p.len = 100;
        p.data = ic_ingest_buf(&p.len, SEPARATOR, 4, 20, 0);
        p.index = 0;
        p.stride = 0;

        pattern_alloc(page, page_size, p);
        fault_cnt++;

        uffdio_copy.src = (unsigned long) page;

        /* We need to handle page faults in units of pages(!).
           So, round faulting address down to page boundary. */

        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
            ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1){
            debug_printf("%s","ioctl-UFFDIO_COPY\n");
            exit(1);
        }
    }
}
static void uffd_start(void){
    pthread_t thr;
    int s = pthread_create(&thr, NULL, uffd_worker, NULL);
    if (s != 0) {
        printf("pthread_create\n");
        exit(1);
    }
}

void bloatme(void){
    uint64_t sz = 4096;

    uffd_setup();
    uffd_start();
    for(int i=0; i<64; i++){
        printf("Trying: %lx... ", sz);
        void *ret = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE, -1, 0);
        if(ret != MAP_FAILED){
            printf("Success! %p\n", ret);
            munmap(ret, sz);
        }
        else{
            printf("Fail!\n");
            break;
        }
        sz = sz << 1;
    }
    sz = sz >> 1;
    void *good = NULL;
    while(1){
        if (sz < 4096<<8)
            break;
        printf("Trying: %lx... ", sz);
        void *ret = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE, -1, 0);
        if(ret != MAP_FAILED && ret){
            printf("Success! %p\n", ret);
            if(ret < (void*)min_addr)
                min_addr = (size_t)ret;
            if((size_t)ret + sz > max_addr)
                max_addr = (size_t)ret + sz;
            uffd_register((size_t)ret, sz, UFFDIO_REGISTER_MODE_MISSING);
        } else {
            printf("Fail!\n");
            sz = sz >> 1;
        }
    }
    printf("MIN_ADDR: %lx MAX_ADDR %lx\n", min_addr, max_addr);
    char path[100];
    sprintf(path, "cat /proc/%d/maps", getpid());
    printf("%s\n", path);
    system(path);
    sprintf(path, "ls -ltrha /proc/%d/fd/", getpid());
    printf("%s\n", path);
    system(path);
    system("ps -aux");
    bloated = 1;
    sleep(1);
    fflush(stdout);
}
