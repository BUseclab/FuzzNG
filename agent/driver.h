#ifndef DRIVER_H
#define DRIVER_H

#include "fuzz.h"

struct cfu_details {void* addr; size_t len; int string;};

int get_driver_fd(void);
void driver_watch(void);
void driver_stopwatch(void);
int driver_open(void);
void driver_cleanup(void);

void driver_start_fuzzing(void);
void driver_clear_patterns(void);

int driver_set_reverse_fd_offset(int i);

struct cfu_details driver_get_cfu_details(void);

void driver_complete_cfu(void);

#endif
