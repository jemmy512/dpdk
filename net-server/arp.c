#include "arp.h"

#include <rte_malloc.h>

static struct arp_table* arpt = NULL;

struct arp_table* arp_table_instance(void) {
    if (arpt == NULL) {
        arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
        if (arpt == NULL) {
            rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
        }
        memset(arpt, 0, sizeof(struct  arp_table));
    }

    return arpt;
}

uint8_t* get_arp_mac(uint32_t dst_ip) {
    struct arp_table* table = arp_table_instance();

    for (struct arp_entry* iter = table->entries; iter != NULL; iter = iter->next) {
        if (dst_ip == iter->ip) {
            return iter->hwaddr;
        }
    }

    return NULL;
}

int arp_table_add(uint32_t ip, uint8_t* hwaddr, uint8_t type) {
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

int arp_table_rm(uint32_t ip) {
    struct arp_table* table = arp_table_instance();

    for (struct arp_entry* iter = table->entries; iter != NULL; iter = iter->next) {
        if (ip == iter->ip) {
            list_rm(iter, table->entries);
            return 0;
        }
    }

    return 1;
}