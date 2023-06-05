#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <assert.h>

#include "driver.h"

#define MAGIC 'k'
#define WATCH _IO(MAGIC, 1)
#define STOPWATCH _IO(MAGIC, 2)
#define FUZZINGSTAGE _IO(MAGIC, 3)
#define CLEAR_PATTERNS _IO(MAGIC, 4)
#define SET_REVERSE_FD_OFFSET _IO(MAGIC, 5)
#define CLEANUP _IO(MAGIC, 6)
#define GET_CFU_DETAILS _IOW(MAGIC, 7, struct cfu_details)
#define COMPLETE_CFU _IO(MAGIC, 8)


static int fd;

int get_driver_fd(void){
    return fd;
}
void driver_start_fuzzing(void){
    assert(fd);
    assert(ioctl(fd, FUZZINGSTAGE) == 0);
}

void driver_clear_patterns(void){
    assert(fd);
    assert(ioctl(fd, CLEAR_PATTERNS) == 0);
}

void driver_watch(void){
    assert(fd);
    assert(ioctl(fd, WATCH) == 0);
}

void driver_stopwatch(void){
    assert(fd);
    assert(ioctl(fd, STOPWATCH) == 0);
}

void driver_cleanup(void){
    assert(fd);
    int d=ioctl(fd, CLEANUP);
}

struct cfu_details driver_get_cfu_details(void){
    struct cfu_details ret;
    assert(fd);
    ioctl(fd, GET_CFU_DETAILS, &ret);
    return ret;
}

void driver_complete_cfu(void){
    assert(fd);
    int d=ioctl(fd, COMPLETE_CFU);
}

int driver_set_reverse_fd_offset(int i){
    return ioctl(fd, SET_REVERSE_FD_OFFSET, i);
}

int driver_open(void){
    fd = open("/dev/fuzzer", O_RDWR);
    cfu_worker_start(fd);
    return fd == -1;
}

