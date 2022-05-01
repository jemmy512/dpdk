#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_ip.h>

#include "udp.h"
#include "arp.h"
#include "context.h"

#define UDP_APP_RECV_BUFFER_SIZE 128

int encode_udp_pkt(uint8_t* msg, uint32_t sip, uint32_t dip,
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

struct rte_mbuf* make_udp_mbuf(
    uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t* src_mac, uint8_t* dst_mac,
    uint8_t* data, uint16_t length)
{
    const unsigned total_len = length + 42;

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(get_server_mempool());
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t* pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    encode_udp_pkt(pktdata, sip, dip, sport, dport, src_mac, dst_mac, data, total_len);

    return mbuf;
}

int udp_pkt_handler(struct rte_mbuf* udpmbuf) {
    struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
        udpmbuf, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr)
    );
    struct rte_udp_hdr* udphdr = (struct rte_udp_hdr*)(iphdr + 1);

    struct localhost* host = get_hostinfo_by_ip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if (host == NULL) {
        rte_pktmbuf_free(udpmbuf);
        // printf("not found host\n");
        return -3;
    }

    debug_ip_port("udp_pkt_handler", iphdr->src_addr, iphdr->dst_addr, udphdr->src_port, udphdr->dst_port);

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

    ol->data_len = ntohs(udphdr->dgram_len) - sizeof(struct rte_udp_hdr);
    ol->data = rte_malloc("unsigned char*", ol->data_len, 0);
    if (ol->data == NULL) {
        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);
        return -2;
    }
    rte_memcpy(ol->data, (unsigned char*)(udphdr+1), ol->data_len);

    rte_ring_mp_enqueue(host->rcvbuf, ol);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(udpmbuf);

    return 0;
}

int main_udp_server(UN_USED void* arg) {
    printf("main_udp_server starting...\n");

    int connfd = net_socket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        printf("sockfd failed\n");
        return -1;
    }

    struct sockaddr_in localaddr, clientaddr;
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8889);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = get_local_ip();

    net_bind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

    char buffer[UDP_APP_RECV_BUFFER_SIZE] = { 0 };
    socklen_t addrlen = sizeof(clientaddr);

    while (1) {
        if (net_recvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, (struct sockaddr*)&clientaddr, &addrlen) <= 0) {
            continue;
        } else {
            printf("main_udp_server ---> data: %s\n", buffer);
            net_sendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
        }
    }

    net_close(connfd);
}

int udp_server_out(void) {
    for (struct localhost* host = host_table; host != NULL; host = host->next) {
        struct offload* ol;
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void**)&ol);
        if (nb_snd < 0) continue;

        struct in_addr addr;
        addr.s_addr = ol->dip;
        printf("udp_out ---> src [%s:%d]", inet_ntoa(addr), ntohs(ol->dport));

        uint8_t* dst_mac = get_arp_mac(ol->dip);
        if (dst_mac == NULL) {
            struct rte_mbuf* arpbuf = make_arp_mbuf(
                RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip
            );

            struct inout_ring* ring = get_server_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);

            rte_ring_mp_enqueue(host->sndbuf, ol);
        } else {
            struct rte_mbuf* udpbuf = make_udp_mbuf(
                ol->sip, ol->dip, ol->sport, ol->dport,
                host->localmac, dst_mac, ol->data, ol->data_len
            );

            printf(", data: %s", ol->data);

            struct inout_ring* ring = get_server_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&udpbuf, 1, NULL);
        }
    }

    return 0;
}