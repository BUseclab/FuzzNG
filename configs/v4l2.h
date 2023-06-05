char     *conf_name = "v4l2";
fdconf   conf_fds[] = {{"/dev/video0", O_RDWR},{"/dev/video1", O_RDWR},{"/dev/video2", O_RDWR},{"/dev/video10", O_RDWR},{"/dev/swradio0", O_RDWR},{"/dev/radio0", O_RDWR},{"/dev/vbi0", O_RDWR},{"/dev/cec0", O_RDWR},{"/dev/v4l-subdev0", O_RDWR}};
uint64_t conf_initscs[][6] = {{}};
scconf   conf_scs[] = {
    {.nr = __NR_ioctl, .args = 3, .mask_enabled = 1, .mask = {0xFFF, -1, -1, -1, -1, -1}},
    {.nr = __NR_mmap, .args = 6, .mask_enabled = 1, .mask = {0, 0xF000, PROT_READ | PROT_WRITE, MAP_SHARED|MAP_POPULATE, 0xFFFF, -1}},
    {.nr = __NR_close, .args = 1, .mask_enabled = 1, .mask = {0xFFF, -1, -1, -1, -1, -1}},
    {.nr = __NR_read, .args = 3, .mask_enabled = 1, .mask = {0xFFF, -1, 0xFFFF, -1, -1, -1}},
    {.nr = __NR_write, .args = 3, .mask_enabled = 1, .mask = {0xFFF, -1, 0xFFFF, -1, -1, -1}
    },{.nr = __NR_ppoll, .args = 4, .mask_enabled = 1, .mask = {-1, 0xFFF, -1, -1, -1, -1}}
};
