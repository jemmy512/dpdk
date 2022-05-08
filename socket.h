#pragma once

#include <sys/queue.h>
#include <sys/socket.h>
#include <pthread.h>

#include <rte_ether.h>

#include "list.h"

#define UN_USED __attribute__((unused))

int net_socket(UN_USED int domain, int type, UN_USED uint8_t protocol);
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

struct sock_key {
    rte_be32_t sip;
    rte_be32_t dip;
    rte_be16_t sport;
    rte_be16_t dport;
    uint8_t protocol;
};

struct sock {
    int fd;
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
    uint8_t smac[RTE_ETHER_ADDR_LEN];
    uint8_t dmac[RTE_ETHER_ADDR_LEN];

    uint64_t status;

    struct sock* prev;
    struct sock* next;
    wait_queue_entry_t wait_queue;

    union {
        struct {
            LIST_HEAD(, sock) accept_head;
            LIST_ENTRY(sock) accept_entry;
        };

        struct {
            uint32_t snd_nxt;
            uint32_t rcv_nxt;
            struct rte_ring* sndbuf;
            struct rte_ring* rcvbuf;
        };
    };

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

struct offload {
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    uint8_t protocol;

    unsigned char* data;
    uint16_t data_len;
};

void init_sock_table(void);
struct rte_hash* get_sock_table(void);
struct sock* get_udp_sock(uint32_t sip, uint16_t sport);
struct sock* get_tcp_sock(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
struct sock* get_listen_sock(uint32_t sip, uint16_t sport);
struct sock* get_accept_sock(struct sock* sk);
int add_accept_sock(struct sock* listensk, struct sock *sk);

void sock_add(struct sock* sk);
void sock_rm(struct sock* sk);

void print_key(struct sock_key* sk);
void debug_ip_port(const char* name, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t protocol);