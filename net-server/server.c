#include "server.h"

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <pthread.h>

#include "socket.h"
#include "list.h"
#include "tcp.h"
#include "udp.h"
#include "arp.h"
#include "icmp.h"
#include "context.h"

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

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

    init_server_context();

    // init_arp_timer(mbuf_pool);

    struct inout_ring* ring = get_server_ring();

    uint32_t lcore_1 = rte_get_next_lcore(-1, 1, 0);
	uint32_t lcore_2 = rte_get_next_lcore(lcore_1, 1, 0);

    rte_eal_remote_launch(pkt_handler, mbuf_pool, lcore_1);
    rte_eal_remote_launch(main_udp_server, mbuf_pool, lcore_2);
    rte_eal_remote_launch(main_tcp_server, mbuf_pool, lcore_2);

    while (1) {
        // arp_timer_tick();

        struct rte_mbuf* rx_mbuf[BURST_SIZE];
        unsigned nb_rx = rte_eth_rx_burst(get_dpdk_port(), 0, rx_mbuf, BURST_SIZE);
        if (nb_rx > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        } else if (nb_rx > 0) {
            rte_ring_sp_enqueue_burst(ring->in, (void**)rx_mbuf, nb_rx, NULL);
        }

        struct rte_mbuf* tx_mbuf[BURST_SIZE];
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx_mbuf, BURST_SIZE, NULL);
        if (nb_tx > 0) {
            rte_eth_tx_burst(get_dpdk_port(), 0, tx_mbuf, nb_tx);
            for (unsigned int i = 0; i < nb_tx; ++i) {
                rte_pktmbuf_free(tx_mbuf[i]);
            }
        }
    }
}

void init_port(struct rte_mempool* mbuf_pool) {
    uint16_t dev_count= rte_eth_dev_count_avail();
    if (dev_count == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(get_dpdk_port(), &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(get_dpdk_port(), num_rx_queues, num_tx_queues, &port_conf);

    const int socket_id = rte_eth_dev_socket_id(get_dpdk_port());
    if (rte_eth_rx_queue_setup(get_dpdk_port(), 0, 1024, socket_id, NULL, mbuf_pool) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(get_dpdk_port(), 0 , 1024, socket_id, &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }

    if (rte_eth_dev_start(get_dpdk_port()) < 0 ) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

int pkt_handler(void* arg) {
    printf("pkt_handler started\n");

    struct rte_mempool* mbuf_pool = (struct rte_mempool*)arg;
    struct inout_ring* ring = get_server_ring();

    while (1) {
        struct rte_mbuf* mbufs[BURST_SIZE];
        unsigned nb_rx = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);

        for (unsigned i = 0; i < nb_rx; ++i) {
            struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
                mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr)
            );

            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                arp_pkt_handler(mbuf_pool, mbufs[i], ehdr);
            } else if (iphdr->next_proto_id == IPPROTO_TCP) {
                tcp_pkt_handler(mbufs[i]);
            } else if (iphdr->next_proto_id == IPPROTO_UDP) {
                udp_pkt_handler(mbufs[i]);
            } else if (iphdr->next_proto_id == IPPROTO_ICMP) {
                icmp_pkt_handler(mbuf_pool, mbufs[i], ehdr);
            } else {
                rte_pktmbuf_free(mbufs[i]);
            }
        }

        udp_server_out(mbuf_pool);

        tcp_server_out(mbuf_pool);
    }

    return 0;
}