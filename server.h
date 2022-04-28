#pragma once

#include <rte_ether.h>

#include "socket.h"

#define BURST_SIZE 32

struct inout_ring* get_server_ring(void);

void init_port();

int pkt_handler(void* arg);