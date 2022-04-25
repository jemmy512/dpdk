#pragma once

#include <rte_ether.h>

#define list_add(item, list) do { \
    item->prev = NULL; \
    item->next = list; \
    if (list != NULL) list->prev = item; \
    list = item; \
} while (0)

#define list_rm(item, list) do { \
    if (item->prev != NULL) item->prev->next = item->next; \
    if (item->next != NULL) item->next->prev = item->prev; \
    if (list == item) list = item->next; \
    item->prev = item->next = NULL; \
} while (0)

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

static struct  arp_table* arpt = NULL;

static struct  arp_table* arp_table_instance(void) {
    if (arpt == NULL) {
        arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
        if (arpt == NULL) {
            rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
        }
        memset(arpt, 0, sizeof(struct  arp_table));
    }

    return arpt;
}

static uint8_t* get_arp_entry(uint32_t dst_ip) {
    struct arp_table* table = arp_table_instance();

    for (struct arp_entry* iter = table->entries; iter != NULL; iter = iter->next) {
        if (dst_ip == iter->ip) {
            return iter->hwaddr;
        }
    }

    return NULL;
}

static int arp_table_add(uint32_t ip, uint8_t* hwaddr, uint8_t type) {
    struct arp_entry* entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);

    if (entry) {
        memset(entry, 0, sizeof(struct arp_entry));

        entry->ip = ip;
        rte_memcpy(entry->hwaddr, hwaddr, RTE_ETHER_ADDR_LEN);
        entry->type = type;

        struct arp_table* table = arp_table_instance();
        list_add(entry, table->entries);
        table->count ++;

        return 0;
    }

    return 1;
}

static int arp_table_rm(uint32_t ip) {
    struct arp_table* table = arp_table_instance();

    for (struct arp_entry* iter = table->entries; iter != NULL; iter = iter->next) {
        if (ip == iter->ip) {
            list_rm(iter, table->entries);
            return 0;
        }
    }

    return 1;
}