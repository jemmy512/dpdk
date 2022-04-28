#pragma once

#include <arpa/inet.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "socket.h"

int encode_udp_pkt(uint8_t* msg, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t* src_mac, uint8_t* dst_mac,
    unsigned char* data, uint16_t total_len);

struct rte_mbuf* make_udp_mbuf(
    uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t* src_mac, uint8_t* dst_mac,
    uint8_t* data, uint16_t length);

int udp_pkt_handler(struct rte_mbuf* udpmbuf);

int main_udp_server(__attribute__((unused)) void* arg);

int udp_server_out();