#pragma once

#include <rte_ether.h>

#define NUM_MBUFS (4096-1)

#define BURST_SIZE 32
#define RING_SIZE 1024

#define UDP_APP_RECV_BUFFER_SIZE 128

#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6

#define Local_IP_Addr "192.168.71.67"

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))


struct inout_ring {
    struct rte_ring* in;
    struct rte_ring* out;
};

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

struct localhost* get_hostinfo_by_fd(int sockfd);

struct localhost* get_hostinfo_by_fd_by_ip_port(uint32_t dip, uint16_t port, uint8_t proto);