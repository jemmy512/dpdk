#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_timer.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <stdio.h>
#include <pthread.h>

#include "list.h"

#define NUM_MBUFS (4096-1)

#define BURST_SIZE 32
#define RING_SIZE 1024

#define UDP_APP_RECV_BUFFER_SIZE 128

#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6

#define Local_IP_Addr "192.168.71.67"

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

struct inout_ring {
    struct rte_ring* in;
    struct rte_ring* out;
};

static struct inout_ring* ring_ins = NULL;

static struct inout_ring* get_ring(void) {
    if (ring_ins == NULL) {
        ring_ins = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(ring_ins, 0, sizeof(struct inout_ring));
    }

    if (ring_ins == NULL) {
        rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
    }

    if (ring_ins->in == NULL) {
        ring_ins->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    if (ring_ins->out == NULL) {
        ring_ins->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }

    return ring_ins;
}


struct offload {
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;

    unsigned char* data;
    uint16_t length;
};

struct localhost {
    int fd;
    uint32_t localip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    uint8_t protocol;

    struct rte_ring* sndbuf;
    struct rte_ring* rcvbuf;

    struct localhost* prev;
    struct localhost* next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

static struct localhost* lhost = NULL;

#define DEFAULT_FD_NUM	3

static int get_fd_frombitmap(void) {
    int fd = DEFAULT_FD_NUM;
    return fd;
}

static struct localhost* get_hostinfo_by_fd(int sockfd) {
    for (struct localhost* host = lhost; host != NULL; host = host->next) {
        if (sockfd == host->fd) {
            return host;
        }
    }

    return NULL;
}

static struct localhost* get_hostinfo_by_fd_by_ip_port(uint32_t dip, uint16_t port, uint8_t proto) {
    for (struct localhost* host = lhost; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport && proto == host->protocol) {
            return host;
        }
    }

    return NULL;
}

static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol) {
    const int fd = get_fd_frombitmap();

    struct localhost* host = rte_malloc("localhost", sizeof(struct localhost), 0);
    if (host == NULL) {
        return -1;
    }
    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;

    if (type == SOCK_DGRAM)
        host->protocol = IPPROTO_UDP;
    else if (type == SOCK_STREAM)
        host->protocol = IPPROTO_TCP;

    host->rcvbuf = rte_ring_create("rcv buffer", RING_SIZE, rte_socket_id(), 0);
    if (host->rcvbuf == NULL) {
        rte_free(host);
        return -1;
    }

    host->sndbuf = rte_ring_create("snd buffer", RING_SIZE, rte_socket_id(), 0);
    if (host->sndbuf == NULL) {
        rte_ring_free(host->rcvbuf);
        rte_free(host);
        return -1;
    }

    pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &init_cond, sizeof(pthread_cond_t));

    pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &init_mutex, sizeof(pthread_mutex_t));

    list_add(host, lhost);

    return fd;
}

static int nbind(int sockfd, const struct sockaddr* addr, __attribute__((unused)) socklen_t addrlen) {
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL)
        return -1;

    const struct sockaddr_in* laddr = (const struct sockaddr_in*)addr;
    host->localport = laddr->sin_port;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    return 0;
}

static ssize_t nrecvfrom(
    int sockfd, void* buf, size_t len, __attribute__((unused)) int flags,
    struct sockaddr* src_addr, __attribute__((unused)) socklen_t* addrlen)
{
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL) return -1;

    struct offload* ol = NULL;
    unsigned char* ptr = NULL;

    struct sockaddr_in* saddr = (struct sockaddr_in*)src_addr;

    int nb = -1;
    pthread_mutex_lock(&host->mutex);
    while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void**)&ol)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);

    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

    if (len < ol->length) {
        rte_memcpy(buf, ol->data, len);

        ptr = rte_malloc("unsigned char* ", ol->length-len, 0);
        rte_memcpy(ptr, ol->data+len, ol->length-len);

        ol->length -= len;
        rte_free(ol->data);
        ol->data = ptr;

        rte_ring_mp_enqueue(host->rcvbuf, ol);
    } else {
        len = ol->length;
        rte_memcpy(buf, ol->data, len);

        rte_free(ol->data);
        rte_free(ol);
    }

    return len;
}

static ssize_t nsendto(
    int sockfd, const void* buf, size_t len, __attribute__((unused)) int flags,
    const struct sockaddr* dest_addr, __attribute__((unused)) socklen_t addrlen)
{
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL)
        return -1;

    const struct sockaddr_in* daddr = (const struct sockaddr_in*)dest_addr;

    struct offload* ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL)
        return -1;

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->localip;
    ol->sport = host->localport;
    ol->length = len;

    struct in_addr addr;
    addr.s_addr = ol->dip;
    printf("nsendto ---> src [%s:%d], data: %s", inet_ntoa(addr), ntohs(ol->dport), (const char*)buf);

    ol->data = rte_malloc("unsigned char* ", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);

    rte_ring_mp_enqueue(host->sndbuf, ol);

    return len;
}

static int nclose(int fd) {
    struct localhost* host = get_hostinfo_by_fd(fd);
    if (host == NULL) {
        return -1;
    }

    list_rm(host, lhost);

    if (host->rcvbuf) {
        rte_ring_free(host->rcvbuf);
    }
    if (host->sndbuf) {
        rte_ring_free(host->sndbuf);
    }

    rte_free(host);

    return 0;
}

static int encode_udp_pkt(uint8_t* msg, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t* src_mac, uint8_t* dst_mac,
    unsigned char* data, uint16_t total_len)
{
    // 1 ethhdr
    struct rte_ether_hdr* ehdr = (struct rte_ether_hdr*)msg;
    rte_memcpy(ehdr->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ehdr->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 iphdr
    struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->src_addr = sip;
    iphdr->dst_addr = dip;

    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    // 3 udphdr
    struct rte_udp_hdr* udphdr = (struct rte_udp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udphdr->src_port = sport;
    udphdr->dst_port = dport;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udphdr->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udphdr+1), data, udplen);

    udphdr->dgram_cksum = 0;
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);

    return 0;
}

static struct rte_mbuf* make_udp_mbuf(
    struct rte_mempool* mbuf_pool, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t* src_mac, uint8_t* dst_mac,
    uint8_t* data, uint16_t length)
{
    const unsigned total_len = length + 42;

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t* pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    encode_udp_pkt(pktdata, sip, dip, sport, dport, src_mac, dst_mac, data, total_len);

    return mbuf;
}

static int udp_pkt_handler(struct rte_mbuf* udpmbuf) {
    struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
        udpmbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr)
    );
    struct rte_udp_hdr* udphdr = (struct rte_udp_hdr*)(iphdr + 1);

    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    printf("udp_pkt_handler ---> src [%s:%d]", inet_ntoa(addr), ntohs(udphdr->src_port));

    struct localhost* host = get_hostinfo_by_fd_by_ip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if (host == NULL) {
        rte_pktmbuf_free(udpmbuf);
        printf("not found host\n");
        return -3;
    }

    struct offload* ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -1;
    }

    ol->dip = iphdr->dst_addr;
    ol->sip = iphdr->src_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;
    ol->protocol = IPPROTO_UDP;

    ol->length = ntohs(udphdr->dgram_len) - sizeof(struct rte_udp_hdr);
    ol->data = rte_malloc("unsigned char*", ol->length, 0);
    if (ol->data == NULL) {
        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);
        return -2;
    }
    rte_memcpy(ol->data, (unsigned char*)(udphdr+1), ol->length);

    printf(", data: %s", ol->data);

    rte_ring_mp_enqueue(host->rcvbuf, ol);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(udpmbuf);

    return 0;
}

static int main_udp_server(__attribute__((unused)) void* arg) {
    printf("main_udp_server started\n");

    int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        printf("sockfd failed\n");
        return -1;
    }

    struct sockaddr_in localaddr, clientaddr;
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8889);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr(Local_IP_Addr);

    nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

    char buffer[UDP_APP_RECV_BUFFER_SIZE] = { 0 };
    socklen_t addrlen = sizeof(clientaddr);

    while (1) {
        if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, (struct sockaddr*)&clientaddr, &addrlen) <= 0) {
            continue;
        } else {
            printf("main_udp_server ---> src [%s:%d], data: %s", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), buffer);
            nsendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
        }
    }

    nclose(connfd);
}

static int udp_out(struct rte_mempool* mbuf_pool) {
    for (struct localhost* host = lhost; host != NULL; host = host->next) {
        struct offload* ol;
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void**)&ol);
        if (nb_snd < 0) continue;

        struct in_addr addr;
        addr.s_addr = ol->dip;
        printf("udp_out ---> src [%s:%d]", inet_ntoa(addr), ntohs(ol->dport));

        // TODO uint8_t* dst_mac = get_arp_entry(ol->dip);
        uint8_t dst_mac[RTE_ETHER_ADDR_LEN] = { 0x88, 0x66, 0x5a, 0x53, 0x3a, 0xd0 };
        if (dst_mac == NULL) {
            // struct rte_mbuf* arpbuf = send_arp(
            //     mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip
            // );

            // struct inout_ring* ring = get_ring();
            // rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);

            // rte_ring_mp_enqueue(host->sndbuf, ol);
        } else {
            struct rte_mbuf* udpbuf = make_udp_mbuf(
                mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
                host->localmac, dst_mac, ol->data, ol->length
            );

            printf(", data: %s", ol->data);

            struct inout_ring* ring = get_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&udpbuf, 1, NULL);
        }
    }

    return 0;
}

static int pkt_handler(void* arg) {
    printf("pkt_handler started\n");

    struct rte_mempool* mbuf_pool = (struct rte_mempool*)arg;
    struct inout_ring* ring = get_ring();

    while (1) {
        struct rte_mbuf* mbufs[BURST_SIZE];
        unsigned nb_rx = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);

        for (unsigned i = 0; i < nb_rx; ++i) {
            struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

            struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
                mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr)
            );

            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                // arp_pkt_handler(mbuf_pool, mbufs[i], ehdr);
            } else if (iphdr->next_proto_id == IPPROTO_UDP) {
                udp_pkt_handler(mbufs[i]);
            } else if (iphdr->next_proto_id == IPPROTO_ICMP) {
                // icmp_pkt_handler(mbuf_pool, mbufs[i], ehdr);
            } else {
                rte_pktmbuf_free(mbufs[i]);
            }
        }

        udp_out(mbuf_pool);
    }

    return 0;
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
    printf("local mac: %s\n", ether_ntoa((struct ether_addr*)gSrcMac));

    // init arp timer

    // uint8_t mac_arr[RTE_ETHER_ADDR_LEN] = { 0x88, 0x66, 0x5a, 0x53, 0x3a, 0xd0 };
    // uint8_t* mac_addr = rte_malloc("192.168.70.174", RTE_ETHER_ADDR_LEN, 0);
    // rte_memcpy(mac_addr, &mac_arr, RTE_ETHER_ADDR_LEN);
    // arp_table_add(inet_addr("192.168.70.174"), mac_addr, 0);

    struct inout_ring* ring = get_ring();

    uint32_t lcore_1 = rte_get_next_lcore(-1, 1, 0);
	uint32_t lcore_2 = rte_get_next_lcore(lcore_1, 1, 0);

    rte_eal_remote_launch(pkt_handler, mbuf_pool, lcore_1);
    rte_eal_remote_launch(main_udp_server, mbuf_pool, lcore_2);

    while (1) {
        // arp_timer_tick();

        struct rte_mbuf* rx_mbuf[BURST_SIZE];
        unsigned nb_rx = rte_eth_rx_burst(gDpdkPortId, 0, rx_mbuf, BURST_SIZE);
        if (nb_rx > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        } else if (nb_rx > 0) {
            rte_ring_sp_enqueue_burst(ring->in, (void**)rx_mbuf, nb_rx, NULL);
        }

        struct rte_mbuf* tx_mbuf[BURST_SIZE];
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx_mbuf, BURST_SIZE, NULL);
        if (nb_tx > 0) {
            rte_eth_tx_burst(gDpdkPortId, 0, tx_mbuf, nb_tx);
            for (unsigned int i = 0; i < nb_tx; ++i) {
                rte_pktmbuf_free(tx_mbuf[i]);
            }
        }
    }
}