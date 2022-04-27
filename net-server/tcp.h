#pragma once

#include <stdint.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <pthread.h>

#include "socket.h"

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


struct tcp_stream {
    int fd;

    uint32_t dip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t dport;

    uint8_t protocol;

    uint16_t sport;
    uint32_t sip;

    uint32_t snd_nxt;
    uint32_t rcv_nxt;

    TCP_STATUS status;
#if 0
    union {

        struct {
            struct tcp_stream* syn_set; //
            struct tcp_stream* accept_set; //
        };

        struct {
            struct rte_ring* sndbuf;
            struct rte_ring* rcvbuf;
        };
    };
#else
    struct rte_ring* sndbuf;
    struct rte_ring* rcvbuf;
#endif
    struct tcp_stream* prev;
    struct tcp_stream* next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

struct tcp_table {
    int count;
    //struct tcp_stream* listener_set;
    struct tcp_stream* tcb_set;
};

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

struct tcp_table* get_tcp_table(void);

int tcp_pkt_handler(struct rte_mbuf* tcpmbuf);

struct tcp_stream* tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);
struct tcp_stream* tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

int tcp_enqueue_recvbuffer(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, int tcplen);

int tcp_handle_listen(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, struct rte_ipv4_hdr* iphdr);
int tcp_handle_syn_rcvd(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr);
int tcp_handle_established(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, int tcplen);
int tcp_handle_close_wait(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr);
int tcp_handle_last_ack(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr);

int tcp_send_ackpkt(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr);

int main_tcp_server(__attribute__((unused)) void* arg);
int tcp_server_out(struct rte_mempool *mbuf_pool);

struct tcp_stream* get_accept_stream(uint16_t dport);

int encode_tcp_pkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment);

struct rte_mbuf* make_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment);