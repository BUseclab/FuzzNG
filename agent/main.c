#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>

#include <sched.h>
#include <sys/io.h>
#include <linux/sched.h>
#include <linux/kvm.h>
#include <x86intrin.h>

#include "kcov.h"
#include "fuzz_configs.h"
#include "driver.h"
#include "fuzz.h"
#include "device.h"
#include "conveyor.h"


#define MAX_INPUT_SIZE 4096-sizeof(size_t)
#define __NR_io_uring_setup 425

#define LOOP_OVER_FDS 1


struct{
    size_t len;
    uint8_t data[4096-sizeof(size_t)];
} input __attribute__ ((aligned (4096)));

struct{
    size_t len;
    uint8_t data[4096-sizeof(size_t)];
} output __attribute__ ((aligned (4096)));

typedef struct __attribute__((packed)){
    uint64_t id;
    uint16_t start;
    uint16_t len;
    uint32_t runtime;
    uint32_t success;
    uint32_t n_copy_from_user; // Number of copy_from_user patterns
} log_entry;

struct{
    size_t len;
    log_entry data[4096-sizeof(size_t)/(sizeof(log_entry))];
} syscall_log __attribute__ ((aligned (4096)));

int tracepc;
static int abort_errors;
int pattern_allocs;

void pattern_alloc(void* ptr, size_t len, pattern p)
{
    int i;
    uint8_t *buf = ptr;
    uint8_t sum = 0;
    if(!p.len)
        return;
    for (i = 0; i < len; ++i) {
        buf[i] = p.data[i % p.len];
        if ((i % p.len) == p.index) {
            buf[i] += sum;
            sum += p.stride;
        }
    }
    pattern_allocs++;
    return;
}

uint64_t do_syscall(const scconf* sc, uint32_t* args)
{
    uint64_t ret = 0;
    pattern_allocs = 0;
    debug_printf(">>> syscall(%x, %x, %x, %x, %x, %x, %x) = \n", sc->nr, args[0], args[1],
            args[2], args[3], args[4], args[5]);
    driver_watch();
    ret = syscall(sc->nr, args[0], args[1], args[2], args[3], args[4], args[5]);
    driver_stopwatch();
    debug_printf(" = %ld\n", ret);
    return ret;
}

static void new_syscall(uint64_t id, int start, int end, int success, uint32_t runtime, uint32_t n_copy_from_user) {
    if(syscall_log.len >= sizeof(syscall_log.data)/sizeof(syscall_log.data[0])) {
        debug_printf("%s", "Too many syscalls for the log\n");
        abort();
    }
    syscall_log.data[syscall_log.len].id = id;
    syscall_log.data[syscall_log.len].start = start;
    syscall_log.data[syscall_log.len].len = end-start;
    syscall_log.data[syscall_log.len].runtime = runtime;
    syscall_log.data[syscall_log.len].success = success;
    syscall_log.data[syscall_log.len].n_copy_from_user = n_copy_from_user;

    syscall_log.len++;
}

static void replace_syscall(uint64_t id, int start, int end, int success, uint32_t runtime, uint32_t n_copy_from_user) {
    syscall_log.len--;
    new_syscall(id,start,end,success,runtime, n_copy_from_user);
}


uint8_t fd_offset;

static int op_syscall(int nr)
{
    uint32_t args[7] = {0};
    uint64_t ret;
    const scconf *sc = &conf_scs[nr];
    int i;

    uint16_t start = ic_get_last_token();

    for(i = 0; (i < sc->args); i++){
	    if(sc->mask_enabled){
		    if(ic_ingest32(&args[i], 0, -1, sc->mask[i])){
			    early_exit();
            }
	    } else {
		    if(ic_ingest32(&args[i], 0, -1, -1)){
			    early_exit();
            }
	    }
    }

    uint64_t id = (sc->nr);
    if (sc->identity_arg)
        id |= ((uint64_t)args[sc->identity_arg-1]) << 32;
    else if (sc->nr == SYS_ioctl )
        id |= ((uint64_t)args[1]) << 32;

    if(sc->nr == __NR_write) {
        size_t bufsize = ic_lookahead(SEPARATOR, 4);
        if(bufsize)
            args[2] = bufsize;
    }

    new_syscall(id, start, ic_get_cursor(), 0, 0, 0);
    size_t duration = __rdtsc();

    if(args[0] == get_driver_fd() && sc->identity_arg != 1)
        early_exit();

    if(sc->nr != SYS_mmap && sc->nr != SYS_bpf && sc->nr != __NR_io_uring_setup && sc->nr != SYS_eventfd && args[0] < 3)
        return -1;
    if(fd_offset){
        driver_set_reverse_fd_offset(fd_offset);
    }
    ret = do_syscall(sc, args);

    if(ret == -1)
        fd_offset = fd_offset ? 0 : 1;
    int remaining = -1;
    
    while(ret == (uint64_t)-1 && LOOP_OVER_FDS && remaining && !abort_errors){
        remaining = driver_set_reverse_fd_offset(fd_offset);
        ret = do_syscall(sc, args);
        if(ret != -1)
            break;
        debug_printf("Set FD Offset: %d (%d remaining)", fd_offset, remaining);
        if(remaining < 0 )
            break;
        if(remaining == 0 && fd_offset == 1)
            break;
        fd_offset++;
    }
    if(fd_offset && ret != -1){
        uint8_t fdo_str[] = {'F', 'U', 'Z', 'Z', 0, fd_offset};
        ic_insert(fdo_str, sizeof(fdo_str), start);
    }
    fd_offset = 0;
    if(ret != -1 && ret < 30)
        fcntl(ret, F_SETFL, fcntl(ret, F_GETFL) | O_NONBLOCK);

    if(sc->nr == SYS_mmap && (void*)ret != (void*)-1 && (args[2] & PROT_WRITE)){
        int writelen = args[1] > 0x1000 ? 0x1000 : args[1];
        
        pattern p = {};
        p.len = 100;
        p.data = ic_ingest_buf(&p.len, SEPARATOR, 4, 50, 0);

        memset((void*)ret, 0, 100);
        pattern_alloc((void*)ret, writelen, p);
        if(DEBUG){
            debug_printf("\nWRITE 0x%lx 0x%x ", ret, writelen);
            for(i=0; i< writelen && 0 ; i++){
                debug_printf("%02x", *((uint8_t*)(ret)+i));
            }
            debug_printf("%s", "\n");
        }
    }
    duration = __rdtsc() - duration;
    replace_syscall(id, start, ic_get_cursor(), ret != -1, (unsigned int)duration, pattern_allocs);
    return ret;
}

static void op_set_reverse_fd_offset(void) {
    uint8_t index;
    ic_ingest8(&fd_offset, 0, -1);
    ic_erase_backwards_until_token();
}

int test_one(uint8_t *Data, size_t Size){

    void (*ops[])(void) = {
        [0] = op_set_reverse_fd_offset,
    };

    static const int nr_ops = sizeof(ops) / sizeof((ops)[0]);
    const int nr_cmds = nr_ops + (sizeof(conf_scs))/sizeof(conf_scs[0]);
    size_t cmd_len;
    uint8_t op;
    int n_scs = 0;
    
    ic_new_input(Data, Size);
    do{
        if(!ic_length_until_token(SEPARATOR, 4)){
            ic_erase_backwards_until_token();
            continue;
        }
        if(ic_ingest8(&op, 0, nr_cmds)){
            ic_erase_backwards_until_token();
            continue;
        }
        n_scs++;
        debug_printf("OP: %d\n", op);
        if(op < nr_ops){
            ops[op]();
        } else {
            if(op_syscall(op - nr_ops) == -1 && abort_errors) {
                kcov_reset_coverage();
                return 0;
            }
        }
    } while(ic_advance_until_token(SEPARATOR, 4) && n_scs < 10);
    return 0;
}

void init(void){
    int i;
    int nullfd;
    assert(!driver_open());
    kcov_init();

    nullfd = open("/dev/null", O_RDWR);
    dup2(nullfd, 1024*1024-1);
    

    driver_watch();
    int num_fds = sizeof(conf_fds)/sizeof(conf_fds[0]);
    // Open from last to first (configs have most important fds first)
    for(i = num_fds - 1; num_fds && i >= 0 ; i--){
        int last_open = open(conf_fds[i].path, conf_fds[i].flags);
        printf("Opening %s = %d \n", conf_fds[i].path, last_open);
        fflush(stdout);
        assert(last_open != -1);
        int ret = fcntl(last_open, F_SETFL, fcntl(last_open, F_GETFL) | O_NONBLOCK);
        printf("Fcntl %s = %d \n", conf_fds[i].path, ret);
    }
    for(i=0; i < sizeof(conf_initscs)/sizeof(conf_initscs[0]); i++){
        uint64_t* args = conf_initscs[i];
        printf("init_syscall(%lx, %lx, %lx, %lx, %lx, %lx) = ",
                conf_initscs[i][0],
                conf_initscs[i][1],
                conf_initscs[i][2],
                conf_initscs[i][3],
                conf_initscs[i][4],
                conf_initscs[i][5]);
        fflush(stdout);
        int ret = syscall(conf_initscs[i][0],
                conf_initscs[i][1],
                conf_initscs[i][2],
                conf_initscs[i][3],
                conf_initscs[i][4],
                conf_initscs[i][5]);
        printf("%d\n", ret);
    }
    driver_stopwatch();
    mlockall(MCL_CURRENT);
    bloatme();
}

void abort_input(void) {
    outb(1,0x922 + FUZZ_DEVICE_ABORT_INPUT);
}
void early_exit(void) {
    fflush(stdout);
    outb(1,0x922 + FUZZ_DEVICE_RESET);
}

int main()
{
    input.data[0] = 1;
    output.data[0] = 1;
    syscall_log.data[0].id = 1;

    // Set up input conveyor
    ic_setup(MAX_INPUT_SIZE);
    ic_output(output.data, &output.len, MAX_INPUT_SIZE);

    // Allow interacting with qemu-ng
    ioperm(0x922, FUZZ_DEVICE_OPS_END+4, 1);

    // Configure Fuzzer
    tracepc = inb(0x922);
    set_mode(tracepc);
    outl(virt_to_phys(&syscall_log) ,0x922 + FUZZ_DEVICE_ADD_SYSCALL_LOG);
    abort_errors = inb(0x922 + 4);

    init();
    sleep(1);

    outl(virt_to_phys(&output) ,0x922 + FUZZ_DEVICE_ADD_OUTPUT_REGION);
    outl(virt_to_phys(&input) ,0x922 + FUZZ_DEVICE_ADD_INPUT_REGION);

    if(tracepc){
        kcov_trace_pc();
    } else {
        kcov_trace_cmp();
    }

    driver_start_fuzzing();
    outb(1,0x922 + FUZZ_DEVICE_MAKE_SNAPSHOT);
    outb(1,0x922 + FUZZ_DEVICE_GET_INPUT);
    kcov_reset_coverage();
    syscall_log.len = 0;

    test_one(input.data, input.len);

    /* fflush(stdout); */
    outb(1,0x922 + FUZZ_DEVICE_RESET);

    kcov_reset_coverage();
    _Exit(-1);
}
