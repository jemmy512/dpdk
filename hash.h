#pragma once

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ethdev.h>

#include "socket.h"

void* hash_find(struct rte_hash* table, void* key);

int hash_add(struct rte_hash* table, void* key,void* val);

int hash_rm(struct rte_hash* table, void* key);