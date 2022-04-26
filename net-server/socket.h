#pragma once

#include <sys/socket.h>

#include "server.h"

int get_fd_frombitmap(void);

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol);

int nbind(int sockfd, const struct sockaddr* addr, __attribute__((unused)) socklen_t addrlen);

ssize_t nrecvfrom(
    int sockfd, void* buf, size_t len, __attribute__((unused)) int flags,
    struct sockaddr* src_addr, __attribute__((unused)) socklen_t* addrlen);

ssize_t nsendto(
    int sockfd, const void* buf, size_t len, __attribute__((unused)) int flags,
    const struct sockaddr* dest_addr, __attribute__((unused)) socklen_t addrlen);

int nclose(int fd);