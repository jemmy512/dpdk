#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define ENABLE_SEND 1
#define ENABLE_ARP  1

#define NUM_MBUFS (4096-1)

#define BURST_SIZE  32

static uint32_t gSrcIp;
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;

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

static void encode_udp_pkt(uint8_t* msg, unsigned char* data, uint16_t total_len) {
    // 1. ethhdr
    struct rte_ether_hdr* ethhdr = (struct rte_ether_hdr*)msg;
    rte_memcpy(ethhdr->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethhdr->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    ethhdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2. iphdr
    struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->src_addr = gSrcIp;
    iphdr->dst_addr = gDstIp;

    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    // 3. udphdr
    struct rte_udp_hdr* udphdr = (struct rte_udp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udphdr->src_port = gSrcPort;
    udphdr->dst_port = gDstPort;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udphdr->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udphdr+1), data, udplen);

    udphdr->dgram_cksum = 0;
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);
}

static struct rte_mbuf* make_udp_pkt(struct rte_mempool* mbuf_pool, uint8_t* data, uint16_t length) {
    const unsigned total_len = length + 42;

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t* pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    encode_udp_pkt(pktdata, data, total_len);

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
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
                mbufs[i], struct rte_ipv4_hdr* , sizeof(struct rte_ether_hdr)
            );

            if (iphdr->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr* udphdr = (struct rte_udp_hdr*)(iphdr + 1);

                rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

                uint16_t length = ntohs(udphdr->dgram_len);
                *((char*)udphdr + length) = '\0';

                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d, data: %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), (char*)(udphdr+1));

                struct rte_mbuf* txbuf = make_udp_pkt(mbuf_pool, (uint8_t*)(udphdr+1), length);
                rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                rte_pktmbuf_free(txbuf);
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
}