#include "kni.h"

#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_ethdev.h>

#include <assert.h>

#include "context.h"

/* ifconfig vEth0 192.168.4.94 hw ether xx:xx:xx:xx:xx:xx up */

#define MAX_PACKET_SIZE 2048

#define PKT_BURST_SZ 32

struct rte_kni *global_kni = NULL;

static pthread_t kni_link_tid;

static void log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link);
static void* monitor_port_link_status(UN_USED void *arg);

struct rte_kni* get_kni(void) {
    assert(global_kni);
    return global_kni;
}

static int config_network_if(uint16_t port_id, uint8_t if_up) {
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

static int config_mac_address(uint16_t port_id, uint8_t mac_addr[]) {
    int ret = 0;

    if (!rte_eth_dev_is_valid_port(port_id)) {
        printf("config_mac_address, Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    ret = rte_eth_dev_default_mac_addr_set(port_id, (struct rte_ether_addr *)mac_addr);
    if (ret < 0) {
        printf("config_mac_address, failed to config mac_addr for port %d, mac: %s\n",
            port_id, ether_ntoa((struct ether_addr*)mac_addr)
        );
    }

    printf("Configure mac address of port: %d, mac: %s\n", port_id, ether_ntoa((struct ether_addr*)(mac_addr)));

    return ret;
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

    struct rte_kni_ops ops;
    memset(&ops, 0, sizeof(ops));

    ops.port_id = port_id;
    ops.config_network_if = config_network_if;
    ops.config_mac_address = config_mac_address;

    kni_handle = rte_kni_alloc(get_server_mempool(), &conf, &ops);
    if (!kni_handle) {
        rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", port_id);
    }

    return kni_handle;
}

void init_kni(void) {
    if (-1 == rte_kni_init(get_dpdk_port())) {
        rte_exit(EXIT_FAILURE, "kni init failed\n");
    }

    global_kni = alloc_kni();

    int ret = rte_ctrl_thread_create(&kni_link_tid,
        "KNI link status check", NULL, monitor_port_link_status, NULL
    );
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Could not create link status thread!\n");
}

int is_fwd_to_kni(struct rte_ether_hdr* ehdr) {
    return 0;

    struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr*)(ehdr+1);
    int is_arp = ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
    int is_icmp = iphdr->next_proto_id == IPPROTO_ICMP;

    return (is_arp || is_icmp);

    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;

    char* src_mac = ether_ntoa((struct ether_addr*)&ehdr->s_addr);
    char* src_ip = inet_ntoa(addr);
    if (!strcmp(src_mac, "88:66:5a:53:3a:d0") && !strcmp(src_ip, "192.168.4.234")) {
        struct in_addr addr;
        addr.s_addr = iphdr->src_addr;
        printf("is_fwd_to_kni src: %s, mac:%s, ether[%d], ip[%d]\n", inet_ntoa(addr), src_mac, ntohs(ehdr->ether_type), iphdr->next_proto_id);
        return (is_arp || is_icmp);
    }

    return 0;
}

void kni_out(void) {
    struct rte_mbuf *mbufs[PKT_BURST_SZ];
    int nb_rx = rte_kni_rx_burst(get_kni(), mbufs, PKT_BURST_SZ);
    if (nb_rx > PKT_BURST_SZ) {
        return;
    }

    if (nb_rx > 0) {
        for (int i = 0; i < nb_rx; ++i) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr*)(ehdr + 1);
                struct in_addr addr;
                addr.s_addr = iphdr->dst_addr;
                printf("kni out dst: %s ", inet_ntoa(addr));
            }
            printf("kni ether_type --> %x\n", ntohs(ehdr->ether_type));
        }

        struct inout_ring* ring = get_server_ring();
        int nb_tx = rte_ring_mp_enqueue_burst(ring->out, (void**)mbufs, nb_rx, NULL);

        for (int i = nb_tx; i < nb_rx; ++i) {
            rte_pktmbuf_free(mbufs[i]);
        }
    }
}

static void log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
    if (kni == NULL || link == NULL)
        return;

    if (prev == ETH_LINK_DOWN && link->link_status == ETH_LINK_UP) {
        printf("%s NIC Link is Up %d Mbps %s %s.\n",
            rte_kni_get_name(kni),
            link->link_speed,
            link->link_autoneg ? "(AutoNeg)" : "(Fixed)",
            link->link_duplex ? "Full Duplex" : "Half Duplex"
        );
    } else if (prev == ETH_LINK_UP && link->link_status == ETH_LINK_DOWN) {
        printf("%s NIC Link is Down.\n", rte_kni_get_name(kni));
    }
}

static void* monitor_port_link_status(UN_USED void *arg) {
    int ret;
    int port_id = get_dpdk_port();
    struct rte_eth_link link;

    while (1) {
        rte_delay_ms(500);

        memset(&link, 0, sizeof(link));
        ret = rte_eth_link_get_nowait(port_id, &link);
        if (ret < 0) {
            printf("Get link failed (port %u): %s\n", port_id, rte_strerror(-ret));
            continue;
        }

        /* /sys/devices/virtual/net/%s/carrier */
        int prev = rte_kni_update_link(get_kni(), link.link_status);
        log_link_state(get_kni(), prev, &link);
    }

    return NULL;
}