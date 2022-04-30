#pragma once

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>

#include "context.h"

uint16_t icmp_checksum(uint16_t* addr, int count);

int encode_icmp_pkt(uint8_t* msg, uint8_t* dst_mac,
    uint32_t src_ip, uint32_t dst_ip, uint16_t id, uint16_t seqnb, uint8_t* data, uint16_t data_len);

struct rte_mbuf* make_icmp_mbuf(uint8_t* dst_mac, uint32_t src_ip, uint32_t dst_ip,
    uint16_t id, uint16_t seqnb, uint8_t* data, unsigned data_len);

void icmp_pkt_handler(struct rte_mbuf* mbuf);