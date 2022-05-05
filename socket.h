#pragma once

#include <sys/socket.h>

#include <rte_ether.h>

#define UN_USED __attribute__((unused))

extern struct localhost* host_table;

int net_socket(UN_USED int domain, int type, UN_USED int protocol);
int net_bind(int sockfd, const struct sockaddr* addr, UN_USED socklen_t addrlen);
int net_listen(int sockfd, UN_USED int backlog);
int net_accept(int sockfd, struct sockaddr *addr, UN_USED socklen_t *addrlen);
ssize_t net_send(int sockfd, const void *buf, size_t len,UN_USED int flags);
ssize_t net_recv(int sockfd, void *buf, size_t len, UN_USED int flags);
int net_close(int fd);

ssize_t net_recvfrom(
    int sockfd, void* buf, size_t len, UN_USED int flags,
    struct sockaddr* src_addr, UN_USED socklen_t* addrlen);

ssize_t net_sendto(
    int sockfd, const void* buf, size_t len, UN_USED int flags,
    const struct sockaddr* dst_addr, UN_USED socklen_t addrlen);

struct offload {
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;

    unsigned char* data;
    uint16_t data_len;
};

struct localhost {
    int fd;
    uint32_t localip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;
    uint8_t protocol;
    int wait_len;
    int wait_queue[1024];
    /* the above members must in the same order with tcp_stream */

    struct rte_ring* sndbuf;
    struct rte_ring* rcvbuf;

    struct localhost* prev;
    struct localhost* next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

void* get_hostinfo_by_fd(int sockfd);

struct localhost* get_hostinfo_by_ip_port(uint32_t dip, uint16_t port, uint8_t proto);

void hostinfo_rm(struct localhost* host);

void debug_ip_port(const char* name, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);