#pragma once

#include <rte_mempool.h>

int encode_udp_pkt(uint8_t* msg, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t* src_mac, uint8_t* dst_mac,
    unsigned char* data, uint16_t total_len);

struct rte_mbuf* make_udp_mbuf(
    struct rte_mempool* mbuf_pool, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t* src_mac, uint8_t* dst_mac,
    uint8_t* data, uint16_t length);