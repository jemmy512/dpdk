
#include "hash.h"

#include <rte_hash.h>

static void print_table(struct rte_hash* table) {
    struct net_key* key = NULL;
    struct sock* sk = NULL;
    uint32_t next = 0;

    while (rte_hash_iterate(table, (const void**)&key, (void**)&sk, &next) >= 0) {
        debug_ip_port("tbl i", sk->sip, sk->dip, sk->sport, sk->dport, sk->protocol);
    }
}

void* hash_find(struct rte_hash* table, void* key) {
    void* data = NULL;

   int32_t idx = rte_hash_lookup_data(table, key, &data);
    if (idx < 0) {
        print_key("Not find sock", key);
        print_table(table);
    }

    return data;
}

int hash_add(struct rte_hash* table, void* key, void* val) {
    int ret = rte_hash_add_key_data(table, key, val);
    if (ret) {
        print_key("Add sock failed", key);
        print_table(table);
    } else {
        print_key("Add sock", key);
    }

    return ret;
}

int hash_rm(struct rte_hash* table, void* key) {
    int ret = rte_hash_del_key(table, key);
    if (ret) {
        print_key("Remove sock failed", key);
        print_table(table);
    } else {
        print_key("Remove sock", key);
    }
    return ret;
}