#include "context.h"

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include <netinet/ether.h>

static int dpdk_port = 0;
static uint8_t local_mac[RTE_ETHER_ADDR_LEN];
static struct inout_ring* ring_ins = NULL;

void init_server_context(void) {
    rte_eth_macaddr_get(get_dpdk_port(), (struct rte_ether_addr*)local_mac);
    printf("local mac: %s\n", ether_ntoa((struct ether_addr*)local_mac));
}

int get_dpdk_port(void) {
    return dpdk_port;
}

uint8_t* get_local_mac(void) {
    return local_mac;
}

struct inout_ring* get_server_ring(void) {
    if (ring_ins == NULL) {
        ring_ins = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(ring_ins, 0, sizeof(struct inout_ring));
    }

    if (ring_ins == NULL) {
        rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
    }

    if (ring_ins->in == NULL) {
        ring_ins->in = rte_ring_create(
            "in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ
        );
    }

    if (ring_ins->out == NULL) {
        ring_ins->out = rte_ring_create(
            "out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ
        );
    }

    return ring_ins;
}