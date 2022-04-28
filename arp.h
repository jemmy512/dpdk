#pragma once

#include <rte_ether.h>
#include <rte_timer.h>
#include <rte_ethdev.h>

#include "list.h"

extern uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN];

struct arp_entry {
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t type;

    struct arp_entry* next;
    struct arp_entry* prev;
};

struct arp_table {
    struct arp_entry* entries;
    int count;
};

struct arp_table* get_arp_table(void);
uint8_t* get_arp_mac(uint32_t dst_ip);
int arp_table_add(uint32_t ip, uint8_t* hwaddr, uint8_t type);
int arp_table_rm(uint32_t ip);

int encode_arp_pkt(uint8_t* msg, uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip);
struct rte_mbuf* make_arp_mbuf(uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip);
void debug_arp_table(void);
void arp_pkt_handler(struct rte_mbuf* mbuf, struct rte_ether_hdr* ehdr);
void arp_timer_tick(void);
void init_arp_timer(void);
void arp_request_timer_cb(__attribute__((unused)) struct rte_timer* timer, void* arg);

void print_ethaddr(const char* name, const struct rte_ether_addr* eth_addr);