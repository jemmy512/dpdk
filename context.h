#pragma once

#include <rte_ring.h>

#define RING_SIZE 1024

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

struct inout_ring {
    struct rte_ring* in;
    struct rte_ring* out;
};

int get_dpdk_port(void);

uint8_t* get_local_mac(void);

uint32_t get_local_ip(void);

void init_server_context(void);

struct inout_ring* get_server_ring(void);