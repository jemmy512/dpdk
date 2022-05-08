
#include "hash.h"

#include <rte_hash.h>

struct rte_hash* make_sock_table(const char* name) {
    struct rte_hash_parameters params = {
        .name = name,
        .entries = Table_Size,
        .key_len = sizeof(struct sock_key),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = rte_socket_id(),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY
    };

    return rte_hash_create(&params);
}

static void print_table(struct rte_hash* table) {
    struct net_key* key = NULL;
	struct sock* sk = NULL;
	uint32_t next = 0;

	while (rte_hash_iterate(table, (const void**)&key, (void**)&sk, &next) >= 0) {
        debug_ip_port("entry", sk->sip, sk->dip, sk->sport, sk->dport, sk->protocol);
    }
}

void* hash_find(struct rte_hash* table, void* key) {
    void* data = NULL;

   int32_t idx = rte_hash_lookup_data(table, &key, &data);
    if (idx < 0) {
        printf("Not find sock, ");
        // print_key(key);
        print_table(table);
    }

    return data;
}

int hash_add(struct rte_hash* table, void* key, void* val) {
    int ret = rte_hash_add_key_data(table, key, val);
    if (ret) {
        printf("Add sock failed, ");
        print_key(key);
    }
    return ret;
}

int hash_rm(struct rte_hash* table, void* key) {
    int ret = rte_hash_del_key(table, key);
    if (ret) {
        printf("Remove sock failed, ");
        print_key(key);
    }
    return ret;
}