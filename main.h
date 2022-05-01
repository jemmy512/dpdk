#pragma once

#include <rte_ether.h>

#include "socket.h"

void init_port(void);

int pkt_handler(void* arg);

void launch_servers(void);