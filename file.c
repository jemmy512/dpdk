#include "file.h"

#define DEFAULT_FD_NUM 3

#define MAX_FD_COUNT 1024

static unsigned char fd_table[MAX_FD_COUNT] = {0};

int get_fd(void) {
    for (int fd = DEFAULT_FD_NUM; fd < MAX_FD_COUNT; ++fd) {
        if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
            fd_table[fd/8] |= (0x1 << (fd % 8));
            return fd;
        }
    }

    return -1;
}

int put_fd(int fd) {
    if (fd >= MAX_FD_COUNT)
        return -1;

    fd_table[fd/8] &= ~(0x1 << (fd % 8));

    return 0;
}