#pragma once

#include <rte_ether.h>

#include "list.h"

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

struct  arp_table* arp_table_instance(void);

uint8_t* get_arp_mac(uint32_t dst_ip);

int arp_table_add(uint32_t ip, uint8_t* hwaddr, uint8_t type);

int arp_table_rm(uint32_t ip);