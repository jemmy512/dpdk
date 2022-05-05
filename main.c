#include "main.h"

#include <string.h>
#include <netinet/ether.h>

#include "tcp.h"
#include "udp.h"
#include "arp.h"
#include "icmp.h"
#include "kni.h"
#include "ddos.h"

#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

int main(int argc, char* argv[]) {
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    init_server_context();
    init_port();
    // init_arp_timer();
    // init_kni();

    launch_servers();

    struct inout_ring* ring = get_server_ring();
    struct rte_mbuf* rx_mbuf[BURST_SIZE];
    struct rte_mbuf* tx_mbuf[BURST_SIZE];

    while (1) {
        // arp_timer_tick();

        unsigned nb_rx = rte_eth_rx_burst(get_dpdk_port(), 0, rx_mbuf, BURST_SIZE);
        if (nb_rx > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        } else if (nb_rx > 0) {
            rte_ring_sp_enqueue_burst(ring->in, (void**)rx_mbuf, nb_rx, NULL);
        }

        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx_mbuf, BURST_SIZE, NULL);
        if (nb_tx > 0) {
            rte_eth_tx_burst(get_dpdk_port(), 0, tx_mbuf, nb_tx);
            for (unsigned int i = 0; i < nb_tx; ++i) {
                rte_pktmbuf_free(tx_mbuf[i]);
            }
        }
    }
}

int pkt_handler(UN_USED void* arg) {
    printf("pkt_handler starting...\n");

    struct rte_mbuf* mbufs[BURST_SIZE];
    struct inout_ring* ring = get_server_ring();

    while (1) {
        unsigned nb_rx = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);

        for (unsigned i = 0; i < nb_rx; ++i) {
            if (ddos_detect(mbufs[i])) {
                for (unsigned j = 0; j < nb_rx; ++j) {
                    rte_pktmbuf_free(mbufs[i]);
                    goto out;
                }
            }
        }

        for (unsigned i = 0; i < nb_rx; ++i) {
            struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
                mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr)
            );

            arp_table_add(iphdr->src_addr, ehdr->s_addr.addr_bytes, 0);

            if (is_fwd_to_kni(ehdr)) {
                rte_kni_tx_burst(get_kni(), &mbufs[i], 1);
            }
            else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                arp_pkt_handler(mbufs[i]);
            } else if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                if (iphdr->next_proto_id == IPPROTO_UDP) {
                    udp_pkt_handler(mbufs[i]);
                } else if (iphdr->next_proto_id == IPPROTO_TCP) {
                    tcp_pkt_handler(mbufs[i]);
                } else if (iphdr->next_proto_id == IPPROTO_ICMP) {
                    icmp_pkt_handler(mbufs[i]);
                } else {
                    rte_pktmbuf_free(mbufs[i]);
                }
            }
            else {
                rte_pktmbuf_free(mbufs[i]);
            }
        }

out:
        // rte_kni_handle_request(get_kni());

        // kni_out();

        udp_server_out();

        tcp_server_out();
    }

    return 0;
}

void init_port(void) {
    uint16_t nb_port = rte_eth_dev_count_avail();
    if (nb_port == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    const int port_id = get_dpdk_port();
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);

    const int nb_rx_queue = 1;
    const int nb_tx_queue = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(port_id, nb_rx_queue, nb_tx_queue, &port_conf);

    const int socket_id = rte_eth_dev_socket_id(port_id);
    if (rte_eth_rx_queue_setup(port_id, 0, 1024, socket_id, NULL, get_server_mempool()) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(port_id, 0 , 1024, socket_id, &txq_conf) < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }

    if (rte_eth_dev_start(port_id) < 0 ) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }

    // if (rte_eth_promiscuous_enable(get_dpdk_port())) {
    //     rte_exit(EXIT_FAILURE, "Count not enable promiscuous mode\n");
    // }
}

void launch_servers(void) {
    unsigned lcore_id = rte_lcore_id();
    unsigned lcore_1 = rte_get_next_lcore(lcore_id, 1, 0);
    unsigned lcore_2 = rte_get_next_lcore(lcore_1, 1, 0);
    unsigned lcore_3 = rte_get_next_lcore(lcore_2, 1, 0);
    printf("lcores: %d, %d, %d\n", lcore_1, lcore_2, lcore_3);

    rte_eal_remote_launch(pkt_handler, NULL, lcore_1);
    rte_eal_remote_launch(main_tcp_server, NULL, lcore_2);
    // rte_eal_remote_launch(main_udp_server, NULL, lcore_2);
}