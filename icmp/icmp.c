#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define ENABLE_SEND 1
#define ENABLE_ARP  1

#define NUM_MBUFS (4096-1)

#define BURST_SIZE  32

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

static uint16_t icmp_checksum(uint16_t* addr, int count) {
    register long sum = 0;

    while (count > 1) {
        sum += *(unsigned short*)addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += *(unsigned char*)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

static int encode_icmp_pkt(uint8_t* msg, uint8_t* dst_mac,
    uint32_t src_ip, uint32_t dst_ip, uint16_t id, uint16_t seqnb, uint8_t* data, uint16_t data_len)
{
    // 1 ether
    struct rte_ether_hdr* eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 ip
    struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + data_len);
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_ICMP;
    iphdr->src_addr = src_ip;
    iphdr->dst_addr = dst_ip;

    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    // 3 icmp
    struct rte_icmp_hdr* icmphdr = (struct rte_icmp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    icmphdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_ident = id;
    icmphdr->icmp_seq_nb = seqnb;

    if (data_len > 0) {
        rte_memcpy((uint8_t*)(icmphdr+1), data, data_len);
    }

    icmphdr->icmp_cksum = 0;
    icmphdr->icmp_cksum = icmp_checksum((uint16_t*)icmphdr, sizeof(struct rte_icmp_hdr) + data_len);

    return 0;
}

static struct rte_mbuf* make_icmp_pkt(struct rte_mempool* mbuf_pool, uint8_t* dst_mac,
    uint32_t src_ip, uint32_t dst_ip, uint16_t id, uint16_t seqnb, uint8_t* data, unsigned data_len)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr) + data_len;

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_icmp_pkt(pkt_data, dst_mac, src_ip, dst_ip, id, seqnb, data, data_len);

    return mbuf;
}

static void icmp_handler(struct rte_mempool* mbuf_pool,  struct rte_mbuf* mbuf, struct rte_ether_hdr* ehdr) {
    if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
       return;
    }

    struct rte_ipv4_hdr* iphdr = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr* , sizeof(struct rte_ether_hdr)
    );

    if (iphdr->next_proto_id == IPPROTO_ICMP) {
        struct rte_icmp_hdr* icmphdr = (struct rte_icmp_hdr*)(iphdr + 1);

        struct in_addr addr;
        addr.s_addr = iphdr->src_addr;
        printf("icmp ---> src: %s ", inet_ntoa(addr));

        if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
            addr.s_addr = iphdr->dst_addr;
            printf(" local: %s, type: %d\n", inet_ntoa(addr), icmphdr->icmp_type);

            uint16_t data_len = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_icmp_hdr);

            printf("icmp data len: %d, data: ", data_len);
            for (uint16_t i = 0; i < data_len; ++i) {
                printf("%x-", *((uint16_t*)(icmphdr+1) + i));
            }
            printf("\n");

            struct rte_mbuf* pkt = make_icmp_pkt(mbuf_pool, ehdr->s_addr.addr_bytes,
                iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb,
                (uint8_t*)(icmphdr+1),
                data_len
            );

            rte_eth_tx_burst(gDpdkPortId, 0, &pkt, 1);
            rte_pktmbuf_free(pkt);
        }
    }
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
        unsigned nb_rx = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if (nb_rx > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }

        for (unsigned i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            icmp_handler(mbuf_pool, mbufs[i], ehdr);
            rte_pktmbuf_free(mbufs[i]);
        }
    }
}