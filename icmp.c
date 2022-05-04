#include "icmp.h"

#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_icmp.h>
#include <rte_ring.h>

#include "socket.h"
#include "util.h"

uint16_t icmp_cksum(uint16_t* addr, int count) {
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

int encode_icmp_pkt(uint8_t* msg, uint8_t* dst_mac,
    uint32_t src_ip, uint32_t dst_ip, uint16_t id, uint16_t seqnb, uint8_t* data, uint16_t data_len)
{
    // 1 ether
    struct rte_ether_hdr* eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, get_local_mac(), RTE_ETHER_ADDR_LEN);
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
    icmphdr->icmp_cksum = icmp_cksum((uint16_t*)icmphdr, sizeof(struct rte_icmp_hdr) + data_len);

    return 0;
}

struct rte_mbuf* make_icmp_mbuf(uint8_t* dst_mac,
    uint32_t src_ip, uint32_t dst_ip, uint16_t id, uint16_t seqnb, uint8_t* data, unsigned data_len)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
        sizeof(struct rte_icmp_hdr) + data_len;

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(get_server_mempool());
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_icmp_pkt(pkt_data, dst_mac, src_ip, dst_ip, id, seqnb, data, data_len);

    return mbuf;
}

void icmp_pkt_handler(struct rte_mbuf* mbuf) {
    struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    struct rte_ipv4_hdr* iphdr = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_ipv4_hdr* , sizeof(struct rte_ether_hdr)
    );
    struct rte_icmp_hdr* icmphdr = (struct rte_icmp_hdr*)(iphdr + 1);

    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    printf("icmp ---> src: %s ", inet_ntoa(addr));

    if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
        addr.s_addr = iphdr->dst_addr;
        printf(" local: %s, type: %d\n", inet_ntoa(addr), icmphdr->icmp_type);

        uint16_t data_len = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_icmp_hdr);

        // printf("icmp data ");
        // print_hex((uint8_t*)(icmphdr+1), data_len);

        struct rte_mbuf* mbuf = make_icmp_mbuf(
            ehdr->s_addr.addr_bytes,
            iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb,
            (uint8_t*)(icmphdr+1),
            data_len
        );

        struct inout_ring* ring = get_server_ring();
        rte_ring_mp_enqueue_burst(ring->out, (void**)&mbuf, 1, NULL);
    }
}