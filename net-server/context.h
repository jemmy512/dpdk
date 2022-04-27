#pragma once

#include <rte_ring.h>

#define RING_SIZE 1024

struct inout_ring {
    struct rte_ring* in;
    struct rte_ring* out;
};

int get_dpdk_port(void);

uint8_t* get_local_mac(void);

void init_server_context(void);

struct inout_ring* get_server_ring(void);