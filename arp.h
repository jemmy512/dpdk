#pragma once

#include <rte_ether.h>
#include <rte_timer.h>
#include <rte_ethdev.h>

#include "list.h"

#define UN_USED __attribute__((unused))

extern uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN];

struct arp_entry {
    uint32_t ip;
    uint8_t mac[RTE_ETHER_ADDR_LEN];
    uint8_t type;

    struct arp_entry* next;
    struct arp_entry* prev;
};

struct arp_table {
    int count;
    struct arp_entry* entries;
    pthread_spinlock_t lock;
};

struct arp_table* get_arp_table(void);
uint8_t* get_arp_mac(uint32_t dst_ip);
int arp_table_add(uint32_t ip, uint8_t* mac, uint8_t type);
int arp_table_rm(uint32_t ip);

int encode_arp_pkt(uint8_t* msg, uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip);
struct rte_mbuf* make_arp_mbuf(uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip);
void debug_arp_table(void);
void arp_pkt_handler(struct rte_mbuf* mbuf);
void arp_timer_tick(void);
void init_arp_timer(void);
void arp_request_timer_cb(UN_USED struct rte_timer* timer, UN_USED void* arg);