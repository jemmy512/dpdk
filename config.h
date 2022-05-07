#pragma once

#include <stdint.h>

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

#define ARP_REQ_IP MAKE_IPV4_ADDR(192, 168, 4, 234)

static uint32_t local_ip = MAKE_IPV4_ADDR(192, 168, 4, 137);
