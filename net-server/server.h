#pragma once

#include <rte_ether.h>

#include "socket.h"

#define NUM_MBUFS (4096-1)

#define BURST_SIZE 32

#define Local_IP_Addr "192.168.71.67"

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

struct inout_ring* get_server_ring(void);

void init_port(struct rte_mempool* mbuf_pool);

int pkt_handler(void* arg);