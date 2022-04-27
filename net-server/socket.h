#pragma once

#include <sys/socket.h>

#include <rte_ether.h>

extern struct localhost* host_table;

int net_socket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol);
int net_bind(int sockfd, const struct sockaddr* addr, __attribute__((unused)) socklen_t addrlen);
int net_listen(int sockfd, __attribute__((unused)) int backlog);
int net_accept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen);
ssize_t net_send(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags);
ssize_t net_recv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags);
int net_close(int fd);

ssize_t net_recvfrom(
    int sockfd, void* buf, size_t len, __attribute__((unused)) int flags,
    struct sockaddr* src_addr, __attribute__((unused)) socklen_t* addrlen);

ssize_t net_sendto(
    int sockfd, const void* buf, size_t len, __attribute__((unused)) int flags,
    const struct sockaddr* dest_addr, __attribute__((unused)) socklen_t addrlen);

struct offload {
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;

    unsigned char* data;
    uint16_t length;
};

struct localhost {
    int fd;
    uint32_t localip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    uint8_t protocol;

    struct rte_ring* sndbuf;
    struct rte_ring* rcvbuf;

    struct localhost* prev;
    struct localhost* next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

void* get_hostinfo_by_fd(int sockfd);

struct localhost* get_hostinfo_by_ip_port(uint32_t dip, uint16_t port, uint8_t proto);

void debug_ip_port(const char* name, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);