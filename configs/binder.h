char *conf_name = "binder";
fdconf   conf_fds[] = {{"/dev/binderfs/vndbinder", O_RDWR|O_NONBLOCK}, {"/dev/binderfs/hwbinder", O_RDWR|O_NONBLOCK},{"/dev/binderfs/binder-control", O_RDWR|O_NONBLOCK},{"/dev/binderfs/binder", O_RDWR|O_NONBLOCK},{"/sys/kernel/debug/binder/state", O_RDWR|O_NONBLOCK},{"/sys/kernel/debug/binder/failed_transaction_log", O_RDWR|O_NONBLOCK},{"/sys/kernel/debug/binder/stats", O_RDWR|O_NONBLOCK},{"/sys/kernel/debug/binder/transaction_log", O_RDWR|O_NONBLOCK},{"/sys/kernel/debug/binder/transactions", O_RDWR|O_NONBLOCK}};
uint64_t conf_initscs[][6] = {{}};
scconf   conf_scs[] = {
    {.nr = __NR_ioctl,.args = 3,.mask_enabled = 1,.mask = {0xFFF, -1, -1, -1, -1, -1},},
    {.nr = __NR_mmap,.args = 6,.mask_enabled = 1,.mask = {0, 0xF000, PROT_READ | PROT_WRITE, MAP_SHARED, 0xFFFF, -1},},
    {.nr = __NR_close,.args = 1,.mask_enabled = 1,.mask = {0xFFF, -1, -1, -1, -1, -1},},
    {.nr = __NR_fstat,.args = 2,.mask_enabled = 1,.mask = {0xFFF, -1, -1, -1, -1, -1},},
    {.nr = __NR_read,.args = 3,.mask_enabled = 1,.mask = {0xFFF, -1, 0xFFFF, -1, -1, -1},},
    {.nr = __NR_write,.args = 3,.mask_enabled = 1,.mask = {0xFFF, -1, 0xFFFF, -1, -1, -1},}
};
