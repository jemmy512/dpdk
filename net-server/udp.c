#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_udp.h>
#include <rte_ip.h>

#include "udp.h"

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