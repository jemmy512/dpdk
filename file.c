#include "file.h"

#include <stddef.h>
#include <pthread.h>

#define DEFAULT_FD_NUM 3

#define MAX_FD_COUNT 1024

static void* fd_table[MAX_FD_COUNT] = {0};

static pthread_spinlock_t lock = PTHREAD_PROCESS_SHARED;

int get_fd(void) {
    int ret = -1;

    pthread_spin_lock(&lock);
    for (int fd = DEFAULT_FD_NUM; fd < MAX_FD_COUNT; ++fd) {
        // if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
        //     fd_table[fd/8] |= (0x1 << (fd % 8));
        //     return fd;
        // }

        if (fd_table[fd] == NULL) {
            ret = fd;
            break;
        }
    }
    pthread_spin_unlock(&lock);

    return ret;
}

int put_fd(int fd) {
    if (fd >= MAX_FD_COUNT)
        return -1;

    // fd_table[fd/8] &= ~(0x1 << (fd % 8));

    pthread_spin_lock(&lock);
    fd_table[fd] = NULL;
    pthread_spin_unlock(&lock);

    return 0;
}

int set_fd(int fd, void* data) {
    pthread_spin_lock(&lock);
    fd_table[fd] = data;
    pthread_spin_unlock(&lock);

    return 0;
}

void* find_fd(int fd) {
    if (fd > MAX_FD_COUNT)
        return NULL;

    return fd_table[fd];
}