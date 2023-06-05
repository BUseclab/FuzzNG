char     *conf_name = "bpf"; 
fdconf   conf_fds[] = {}; 
uint64_t conf_initscs[][6] = {}; 
scconf   conf_scs[] = { 
    {
        .nr = __NR_bpf,
        .args = 3,
        .mask_enabled = 1,
        .mask = {-1, -1, -1, -1, -1, -1},
        .identity_arg = 1,
    }
};
