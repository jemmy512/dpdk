#pragma once

#include <rte_ether.h>

#include "socket.h"

#define NUM_MBUFS (4096-1)

#define BURST_SIZE 32

struct inout_ring* get_server_ring(void);

void init_port(struct rte_mempool* mbuf_pool);

int pkt_handler(void* arg);