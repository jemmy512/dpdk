#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include <stdio.h>
#include <arpa/inet.h>

#include "arp.h"

#define NUM_MBUFS (4096-1)

#define BURST_SIZE  32

#define TIMER_RESOLUTION_CYCLES 60000000000ULL // 10ms * 1000 = 10s * 6

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 71, 67);
static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

int gDpdkPortId = 0;

static struct rte_timer arp_timer;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static struct rte_mbuf* make_arp_pkt(
    struct rte_mempool* mbuf_pool, uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip
);

static void arp_request_timer_cb(
    __attribute__((unused)) struct rte_timer* timer, void* arg)
{
    struct rte_mempool* mbuf_pool = (struct rte_mempool*)arg;

    uint32_t arp_req_ip = MAKE_IPV4_ADDR(192, 168, 70, 174);

    for (int i = 100; i <= 255; ++i) {
        uint32_t dstip = (arp_req_ip & 0x00FFFFFF) | (0xFF000000 & (i << 24));

        struct in_addr addr;
        addr.s_addr = dstip;
        printf("arp ping ---> src: %s \n", inet_ntoa(addr));

        struct rte_mbuf* arpbuf = NULL;
        uint8_t* dst_mac = get_dst_macaddr(dstip);

        if (dst_mac == NULL) {
            arpbuf = make_arp_pkt(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
        } else {
            arpbuf = make_arp_pkt(mbuf_pool, RTE_ARP_OP_REQUEST, dst_mac, gLocalIp, dstip);
        }

        rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
        rte_pktmbuf_free(arpbuf);
    }
}

static void init_arp_timer(struct rte_mempool* mbuf_pool) {
    rte_timer_subsystem_init();

    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);
}

static void arp_timer_tick(void) {
    static uint64_t prev_tsc = 0, cur_tsc;
    uint64_t diff_tsc;

    cur_tsc = rte_rdtsc();
    diff_tsc = cur_tsc - prev_tsc;
    if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
        rte_timer_manage();
        prev_tsc = cur_tsc;
    }
}

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

static int encode_arp_pkt(uint8_t* msg, uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip) {
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
    arp->arp_opcode = htons(opcode);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}

static struct rte_mbuf* make_arp_pkt(
    struct rte_mempool* mbuf_pool, uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

    return mbuf;
}

static void print_ethaddr(const char* name, const struct rte_ether_addr* eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

static void debug_arp_table(void) {
    struct arp_table* table = arp_table_instance();

    for (struct arp_entry* iter = table->entries; iter != NULL; iter = iter->next) {

        struct in_addr addr;
        addr.s_addr = iter->ip;

        print_ethaddr("arp table --> mac: ", (struct rte_ether_addr*)iter->hwaddr);
        printf(" ip: %s \n", inet_ntoa(addr));
    }
}

static void arp_handler(struct rte_mempool* mbuf_pool,  struct rte_mbuf* mbuf, struct rte_ether_hdr* ehdr) {
    if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        return;
    }

    struct rte_arp_hdr* arphdr = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_arp_hdr* , sizeof(struct rte_ether_hdr)
    );

    if (arphdr->arp_data.arp_tip == gLocalIp) {
        if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
            printf("arp --> recv req\n");

            struct rte_mbuf* arpbuf = make_arp_pkt(
                mbuf_pool, RTE_ARP_OP_REPLY,
                arphdr->arp_data.arp_sha.addr_bytes,
                arphdr->arp_data.arp_tip,
                arphdr->arp_data.arp_sip
            );

            rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
            rte_pktmbuf_free(arpbuf);

        } else if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
            printf("arp --> recv reply\n");

            uint8_t* hwaddr = get_dst_macaddr(arphdr->arp_data.arp_sip);

            if (hwaddr == NULL) {
                arp_table_add(arphdr->arp_data.arp_sip, arphdr->arp_data.arp_sha.addr_bytes, 0);
            }

            debug_arp_table();
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

    init_arp_timer(mbuf_pool);

    while (1) {
        arp_timer_tick();

        struct rte_mbuf* mbufs[BURST_SIZE];
        unsigned nb_rx = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if (nb_rx > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }

        for (unsigned i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            arp_handler(mbuf_pool, mbufs[i], ehdr);
            rte_pktmbuf_free(mbufs[i]);
        }
    }
}