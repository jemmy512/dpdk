#pragma once

#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <pthread.h>

#include "socket.h"

#define UN_USED __attribute__((unused))

#define TCP_OPTION_LENGTH 10

#define TCP_MAX_SEQ  4294967295

#define TCP_INITIAL_WINDOW  14600

typedef enum _TCP_STATUS {
    TCP_STATUS_CLOSED = 0,
    TCP_STATUS_LISTEN,
    TCP_STATUS_SYN_RCVD,
    TCP_STATUS_SYN_SENT,
    TCP_STATUS_ESTABLISHED,

    TCP_STATUS_FIN_WAIT_1,
    TCP_STATUS_FIN_WAIT_2,
    TCP_STATUS_CLOSING,
    TCP_STATUS_TIME_WAIT,

    TCP_STATUS_CLOSE_WAIT,
    TCP_STATUS_LAST_ACK
} TCP_STATUS;

struct tcp_fragment {
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t  hdrlen_off;
    uint8_t  tcp_flags;
    uint16_t windows;
    uint16_t cksum;
    uint16_t tcp_urp;

    int optlen;
    uint32_t option[TCP_OPTION_LENGTH];

    unsigned char* data;
    uint32_t data_len;
};

int tcp_pkt_handler(struct rte_mbuf* tcpmbuf);

struct sock* tcp_sock_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

int tcp_enqueue_rcvbuf(struct sock* sk, struct rte_tcp_hdr* tcphdr, int tcplen);

int tcp_handle_listen(struct sock* sk, struct rte_tcp_hdr* tcphdr, struct rte_ipv4_hdr* iphdr);
int tcp_handle_syn_rcvd(struct sock* sk, struct rte_tcp_hdr* tcphdr);
int tcp_handle_established(struct sock* sk, struct rte_tcp_hdr* tcphdr, int tcplen);
int tcp_handle_close_wait(struct sock* sk, struct rte_tcp_hdr* tcphdr);
int tcp_handle_last_ack(struct sock* sk, struct rte_tcp_hdr* tcphdr);

int tcp_send_ack(struct sock* sk, struct rte_tcp_hdr* tcphdr);

int main_tcp_server(UN_USED void* arg);
int tcp_server_out(void);

int encode_tcp_pkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *smac, uint8_t *dmac, struct tcp_fragment *fragment);

struct rte_mbuf* make_tcp_pkt(uint32_t sip, uint32_t dip,
	uint8_t *smac, uint8_t *dmac, struct tcp_fragment *fragment);