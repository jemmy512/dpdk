#pragma once

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ethdev.h>

#include "socket.h"

#define Table_Size 8192

struct rte_hash* make_sock_table(const char* name);

void* hash_find(struct rte_hash* table, void* key);

int hash_add(struct rte_hash* table, void* key,void* val);

int hash_rm(struct rte_hash* table, void* key);