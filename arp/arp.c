#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define ENABLE_SEND 1
#define ENABLE_ARP  1

#define NUM_MBUFS (4096-1)

#define BURST_SIZE  32

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 71, 67);

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void init_port(struct rte_mempool* mbuf_pool) {
    uint16_t dev_count= rte_eth_dev_count_avail();
    if (dev_count == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

    const int socket_id = rte_eth_dev_socket_id(gDpdkPortId);
    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, socket_id, NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, socket_id, &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }

    if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

static int encode_arp_pkt(uint8_t* msg, uint8_t* dst_mac, uint32_t sip, uint32_t dip) {
    // 1 ethhdr
    struct rte_ether_hdr* eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // 2 arp
    struct rte_arp_hdr* arp = (struct rte_arp_hdr*)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(2);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}

static struct rte_mbuf* make_arp_pkt(struct rte_mempool* mbuf_pool, uint8_t* dst_mac, uint32_t sip, uint32_t dip) {
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_arp_pkt(pkt_data, dst_mac, sip, dip);

    return mbuf;
}

int main(int argc, char* argv[]) {
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create(
        "mbuf pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()
    );
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    init_port(mbuf_pool);

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*)gSrcMac);

    while (1) {
        struct rte_mbuf* mbufs[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }

        unsigned i = 0;
        for (i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                struct rte_arp_hdr* arphdr = rte_pktmbuf_mtod_offset(
                    mbufs[i], struct rte_arp_hdr* , sizeof(struct rte_ether_hdr)
                );

                struct in_addr addr;
                addr.s_addr = arphdr->arp_data.arp_tip;
                printf("arp ---> src: %s ", inet_ntoa(addr));

                addr.s_addr = gLocalIp;
                printf(" local: %s \n", inet_ntoa(addr));

                if (arphdr->arp_data.arp_tip == gLocalIp) {
                    struct rte_mbuf* arpbuf = make_arp_pkt(
                        mbuf_pool,
                        arphdr->arp_data.arp_sha.addr_bytes,
                        arphdr->arp_data.arp_tip,
                        arphdr->arp_data.arp_sip
                    );

                    rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
                    rte_pktmbuf_free(arpbuf);

                    rte_pktmbuf_free(mbufs[i]);
                }
            }
        }
    }
}