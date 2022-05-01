#include "kni.h"

#include <rte_ether.h>
#include <rte_ethdev.h>

#include <assert.h>

#include "context.h"

#define MAX_PACKET_SIZE 2048

struct rte_kni *global_kni = NULL;

struct rte_kni* get_kni(void) {
    assert(global_kni);
    return global_kni;
}

int config_network_if(uint16_t port_id, uint8_t if_up) {
    if (!rte_eth_dev_is_valid_port(port_id)) {
        return -EINVAL;
    }

    int ret = 0;
    if (if_up) {
        rte_eth_dev_stop(port_id);
        ret = rte_eth_dev_start(port_id);
    } else {
        rte_eth_dev_stop(port_id);
    }

    if (ret < 0) {
        printf("Failed to start kni port : %d\n", port_id);
    } else {
        printf("Success to start kni port : %d\n", port_id);
    }

    return 0;
}

struct rte_kni *alloc_kni(void) {
    struct rte_kni *kni_handle = NULL;

    struct rte_kni_conf conf;
    memset(&conf, 0, sizeof(conf));

    const int port_id = get_dpdk_port();
    snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", port_id);
    conf.group_id = port_id;
    conf.mbuf_size = MAX_PACKET_SIZE;
    rte_eth_macaddr_get(port_id, (struct rte_ether_addr *)conf.mac_addr);
    rte_eth_dev_get_mtu(port_id, &conf.mtu);

/*
    struct rte_eth_dev_info dev_info;
    memset(&dev_info, 0, sizeof(dev_info));
    rte_eth_dev_info_get(port_id, &dev_info);
    */

    struct rte_kni_ops ops;
    memset(&ops, 0, sizeof(ops));

    ops.port_id = port_id;
    ops.config_network_if = config_network_if;

    kni_handle = rte_kni_alloc(get_server_mempool(), &conf, &ops);
    if (!kni_handle) {
        rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", port_id);
    }

    return kni_handle;
}

void init_kni(void) {
    rte_eth_promiscuous_enable(get_dpdk_port());

    if (-1 == rte_kni_init(get_dpdk_port())) {
        rte_exit(EXIT_FAILURE, "kni init failed\n");
    }

    global_kni = alloc_kni();
}

int if_handle_by_kni(struct rte_ether_hdr* ehdr) {
    struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr*)(ehdr+1);

    if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)
        || iphdr->next_proto_id == IPPROTO_ICMP)
    {
        return 1;
    }

    return 0;
}