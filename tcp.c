#include "tcp.h"

#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>

#include "list.h"
#include "socket.h"
#include "arp.h"
#include "context.h"

#define BUFFER_SIZE	1024

#define Server_Port 9999

static struct tcp_table* tcp_table_ins = NULL;

struct tcp_table* get_tcp_table(void) {
    if (tcp_table_ins == NULL) {
        tcp_table_ins = rte_malloc("tcp_table", sizeof(struct tcp_table), 0);
        memset(tcp_table_ins, 0, sizeof(struct tcp_table));
    }
    return tcp_table_ins;
}

void tcp_table_add(struct tcp_stream* stream) {
    struct tcp_table* table = get_tcp_table();
    ++table->count;
    list_add(stream, table->tcb_set);
}

void tcp_table_rm(struct tcp_stream* stream) {
    struct tcp_table* table = get_tcp_table();
    --table->count;
    list_rm(stream, table->tcb_set);

    debug_ip_port("tcp_table_rm", stream->sip, stream->dip, stream->sport, stream->dport);
}

int tcp_pkt_handler(struct rte_mbuf* tcpmbuf) {
    struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
        tcpmbuf, struct rte_ipv4_hdr* , sizeof(struct rte_ether_hdr)
    );
    struct rte_tcp_hdr* tcphdr = (struct rte_tcp_hdr*)(iphdr + 1);

    uint16_t tcpcksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);

    if (cksum != tcpcksum) {
        printf("cksum: %x, tcp cksum: %x\n", cksum, tcpcksum);
        return -1;
    }

    struct tcp_stream* stream = tcp_stream_search(
        iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port
    );
    if (stream == NULL) {
        return -2;
    }

    switch (stream->status) {
        case TCP_STATUS_CLOSED:
            break;

        case TCP_STATUS_LISTEN:
            tcp_handle_listen(stream, tcphdr, iphdr);
            break;

        case TCP_STATUS_SYN_RCVD:
            tcp_handle_syn_rcvd(stream, tcphdr);
            break;

        case TCP_STATUS_SYN_SENT:
            break;

        case TCP_STATUS_ESTABLISHED: {
            int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
            tcp_handle_established(stream, tcphdr, tcplen);
            break;
        }
        case TCP_STATUS_FIN_WAIT_1:
            break;

        case TCP_STATUS_FIN_WAIT_2:
            break;

        case TCP_STATUS_CLOSING:
            break;

        case TCP_STATUS_TIME_WAIT:
            break;

        case TCP_STATUS_CLOSE_WAIT:
            tcp_handle_close_wait(stream, tcphdr);
            break;

        case TCP_STATUS_LAST_ACK:
            tcp_handle_last_ack(stream, tcphdr);
            break;
    }

    printf("tcp_pkt_handler done\n");

    return 0;
}

struct tcp_stream* tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    struct tcp_stream* iter;
    struct tcp_table* table = get_tcp_table();

    for (iter = table->tcb_set; iter != NULL; iter = iter->next) { // established
        if (iter->sip == sip && iter->dip == dip && iter->sport == sport && iter->dport == dport) {
            return iter;
        }
    }

    for (iter = table->tcb_set; iter != NULL; iter = iter->next) {
        if (iter->dport == dport && iter->status == TCP_STATUS_LISTEN) { // listen
            return iter;
        }
    }

    return NULL;
}

struct tcp_stream* tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    struct tcp_stream* stream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
    if (stream == NULL)
        return NULL;
    memset(stream, 0, sizeof(struct tcp_stream));

    stream->sip = sip;
    stream->dip = dip;
    stream->sport = sport;
    stream->dport = dport;
    stream->protocol = IPPROTO_TCP;
    stream->fd = -1; // unused

    stream->status = TCP_STATUS_LISTEN;

    stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
    stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);

    uint32_t next_seed = time(NULL);
    stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
    rte_memcpy(stream->localmac, get_local_mac(), RTE_ETHER_ADDR_LEN);

    pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &init_cond, sizeof(pthread_cond_t));

    pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &init_mutex, sizeof(pthread_mutex_t));

    return stream;
}

int tcp_handle_listen(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, struct rte_ipv4_hdr* iphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG && stream->status == TCP_STATUS_LISTEN) {
        struct tcp_stream* syn_stream = tcp_stream_create(
            iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port
        );
        tcp_table_add(syn_stream);

        struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (frag == NULL)
            return -1;
        memset(frag, 0, sizeof(struct tcp_fragment));

        frag->sport = tcphdr->dst_port;
        frag->dport = tcphdr->src_port;

        frag->seqnum = syn_stream->snd_nxt;
        frag->acknum = ntohl(tcphdr->sent_seq) + 1;
        syn_stream->rcv_nxt = frag->acknum;

        frag->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
        frag->windows = TCP_INITIAL_WINDOW;
        frag->hdrlen_off = 0x50;

        frag->data = NULL;
        frag->data_len = 0;

        rte_ring_mp_enqueue(syn_stream->sndbuf, frag);

        syn_stream->status = TCP_STATUS_SYN_RCVD;

        printf("tcp_handle_listen done\n");
    }

    return 0;
}

int tcp_handle_syn_rcvd(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG && stream->status == TCP_STATUS_SYN_RCVD) {
        uint32_t acknum = ntohl(tcphdr->recv_ack);
        if (acknum == stream->snd_nxt + 1) {

        }

        stream->status = TCP_STATUS_ESTABLISHED;

        // accept
        struct tcp_stream* listener = tcp_stream_search(0, 0, 0, stream->dport);
        if (listener == NULL) {
            rte_exit(EXIT_FAILURE, "tcp_stream_search failed\n");
        }

        pthread_mutex_lock(&listener->mutex);
        pthread_cond_signal(&listener->cond);
        pthread_mutex_unlock(&listener->mutex);
    }

    return 0;
}

int tcp_handle_established(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, int tcplen) {
    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {

    }
    if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {
        // recv buffer
#if 0
        struct tcp_fragment* rfragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (rfragment == NULL) return -1;
        memset(rfragment, 0, sizeof(struct tcp_fragment));

        rfragment->dport = ntohs(tcphdr->dst_port);
        rfragment->sport = ntohs(tcphdr->src_port);

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int data_len = tcplen - hdrlen* 4;
        if (data_len > 0) {

            uint8_t* data = (uint8_t*)tcphdr + hdrlen* 4;

            rfragment->data = rte_malloc("unsigned char* ", data_len+1, 0);
            if (rfragment->data == NULL) {
                rte_free(rfragment);
                return -1;
            }
            memset(rfragment->data, 0, data_len+1);

            rte_memcpy(rfragment->data, data, data_len);
            rfragment->length = data_len;

            printf("tcp : %s\n", rfragment->data);
        }
        rte_ring_mp_enqueue(stream->rcvbuf, rfragment);
#else

        tcp_enqueue_rcvbuf(stream, tcphdr, tcplen);

#endif


#if 0
        // ack pkt
        struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (frag == NULL) return -1;
        memset(frag, 0, sizeof(struct tcp_fragment));

        frag->dport = tcphdr->src_port;
        frag->sport = tcphdr->dst_port;

        // remote

        printf("tcp_handle_established: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));


        stream->rcv_nxt = stream->rcv_nxt + data_len;
        // local
        stream->snd_nxt = ntohl(tcphdr->recv_ack);
        //frag->

        frag->acknum = stream->rcv_nxt;
        frag->seqnum = stream->snd_nxt;

        frag->tcp_flags = RTE_TCP_ACK_FLAG;
        frag->windows = TCP_INITIAL_WINDOW;
        frag->hdrlen_off = 0x50;
        frag->data = NULL;
        frag->length = 0;

        rte_ring_mp_enqueue(stream->sndbuf, frag);

#else

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int data_len = tcplen - hdrlen * 4;

        stream->rcv_nxt = stream->rcv_nxt + data_len;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        tcp_send_ack(stream, tcphdr);

#endif
        // echo pkt
#if 0
        struct tcp_fragment* echofrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (echofrag == NULL) return -1;
        memset(echofrag, 0, sizeof(struct tcp_fragment));

        echofrag->dport = tcphdr->src_port;
        echofrag->sport = tcphdr->dst_port;

        echofrag->acknum = stream->rcv_nxt;
        echofrag->seqnum = stream->snd_nxt;

        echofrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
        echofrag->windows = TCP_INITIAL_WINDOW;
        echofrag->hdrlen_off = 0x50;

        uint8_t* data = (uint8_t*)tcphdr + hdrlen* 4;

        echofrag->data = rte_malloc("unsigned char* ", data_len, 0);
        if (echofrag->data == NULL) {
            rte_free(echofrag);
            return -1;
        }
        memset(echofrag->data, 0, data_len);

        rte_memcpy(echofrag->data, data, data_len);
        echofrag->length = data_len;

        rte_ring_mp_enqueue(stream->sndbuf, echofrag);
#endif
    }

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

    }

    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

        stream->status = TCP_STATUS_CLOSE_WAIT;
#if 0

        struct tcp_fragment* rfragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (rfragment == NULL) return -1;
        memset(rfragment, 0, sizeof(struct tcp_fragment));

        rfragment->dport = ntohs(tcphdr->dst_port);
        rfragment->sport = ntohs(tcphdr->src_port);

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int data_len = tcplen - hdrlen* 4;

        rfragment->length = 0;
        rfragment->data = NULL;

        rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

#else
        tcp_enqueue_rcvbuf(stream, tcphdr, tcphdr->data_off >> 4);

#endif
        // send ack ptk
        stream->rcv_nxt = stream->rcv_nxt + 1;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        tcp_send_ack(stream, tcphdr);

    }

    return 0;
}

int tcp_handle_close_wait(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG && stream->status == TCP_STATUS_CLOSE_WAIT) {

    }

    return 0;
}

int tcp_handle_last_ack(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG && stream->status == TCP_STATUS_LAST_ACK) {
        stream->status = TCP_STATUS_CLOSED;

        tcp_table_rm(stream);

        if (stream->sndbuf) {
            rte_ring_free(stream->sndbuf);
        }
        if (stream->rcvbuf) {
            rte_ring_free(stream->rcvbuf);
        }

        rte_free(stream);
    }

    return 0;
}

int tcp_send_ack(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr) {
    struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
    if (frag == NULL)
        return -1;
    memset(frag, 0, sizeof(struct tcp_fragment));

    frag->dport = tcphdr->src_port;
    frag->sport = tcphdr->dst_port;

    // remote
    printf("tcp_send_ack: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));

    frag->acknum = stream->rcv_nxt;
    frag->seqnum = stream->snd_nxt;

    frag->tcp_flags = RTE_TCP_ACK_FLAG;
    frag->windows = TCP_INITIAL_WINDOW;
    frag->hdrlen_off = 0x50;
    frag->data = NULL;
    frag->data_len = 0;

    rte_ring_mp_enqueue(stream->sndbuf, frag);

    return 0;
}

int tcp_enqueue_rcvbuf(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, int tcplen) {
    struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
    if (frag == NULL)
        return -1;
    memset(frag, 0, sizeof(struct tcp_fragment));

    frag->dport = ntohs(tcphdr->dst_port);
    frag->sport = ntohs(tcphdr->src_port);

    uint8_t hdrlen = tcphdr->data_off >> 4;
    int data_len = tcplen - hdrlen * 4;
    if (data_len > 0) {
        uint8_t* data = (uint8_t*)tcphdr + hdrlen* 4;
        frag->data = rte_malloc("unsigned char* ", data_len+1, 0);
        if (frag->data == NULL) {
            rte_free(frag);
            return -1;
        }
        memset(frag->data, 0, data_len+1);
        rte_memcpy(frag->data, data, data_len);
        frag->data_len = data_len;
    } else if (data_len == 0) {
        frag->data_len = 0;
        frag->data = NULL;
    }
    rte_ring_mp_enqueue(stream->rcvbuf, frag);

    // notify net_recv
    pthread_mutex_lock(&stream->mutex);
    pthread_cond_signal(&stream->cond);
    pthread_mutex_unlock(&stream->mutex);

    return 0;
}

int main_tcp_server(UN_USED void* arg) {
    printf("main_tcp_server staring...\n");

    int listenfd = net_socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1) {
        return -1;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(struct sockaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(Server_Port);
    net_bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    net_listen(listenfd, 10);

    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);
        int connfd = net_accept(listenfd, (struct sockaddr*)&client, &len);

        char buff[BUFFER_SIZE] = {0};
        while (1) {
            int n = net_recv(connfd, buff, BUFFER_SIZE, 0); //block
            if (n > 0) {
                printf("recv: %s\n", buff);
                net_send(connfd, buff, n, 0);
            } else if (n == 0) {
                net_close(connfd);
                break;
            } else {
                // TODO nonblock
            }
        }
    }

    net_close(listenfd);
}

struct tcp_stream* get_accept_stream(uint16_t dport) {
    struct tcp_stream* acpt;
    struct tcp_table* table = get_tcp_table();

    for (acpt = table->tcb_set; acpt != NULL; acpt = acpt->next) {
        if (dport == acpt->dport && acpt->fd == -1) {
            return acpt;
        }
    }

    return NULL;
}

int tcp_server_out(void) {
    struct tcp_table* table = get_tcp_table();

    struct tcp_stream* stream;
    for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
        if (stream->sndbuf == NULL)
            continue; // listener

        struct tcp_fragment* frag = NULL;
        int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&frag);
        if (nb_snd < 0)
            continue;

        printf("tcp_server_out... count: %d\n", table->count);

        uint8_t* dmac = get_arp_mac(stream->sip);
        if (dmac == NULL) {
            // struct rte_mbuf* arpbuf = make_arp_mbuf(
            //     RTE_ARP_OP_REQUEST, gDefaultArpMac, stream->dip, stream->sip
            // );

            // struct inout_ring* ring = get_server_ring();
            // rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
            // rte_ring_mp_enqueue(stream->sndbuf, frag);
        } else {
            struct rte_mbuf* tcpbuf = make_tcp_pkt(
                stream->dip, stream->sip, stream->localmac, dmac, frag
            );
            struct inout_ring* ring = get_server_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&tcpbuf, 1, NULL);

            if (frag->data != NULL)
                rte_free(frag->data);

            rte_free(frag);
        }
    }

    return 0;
}

int encode_tcp_pkt(uint8_t* msg, uint32_t sip, uint32_t dip,
    uint8_t* smac, uint8_t* dmac, struct tcp_fragment* frag)
{
    const unsigned total_len =
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
        sizeof(struct rte_tcp_hdr) + frag->optlen * sizeof(uint32_t) +
        frag->data_len;

    // 1 ethhdr
    struct rte_ether_hdr* ehdr = (struct rte_ether_hdr*)msg;
    rte_memcpy(ehdr->s_addr.addr_bytes, smac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ehdr->d_addr.addr_bytes, dmac, RTE_ETHER_ADDR_LEN);
    ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 iphdr
    struct rte_ipv4_hdr* iphdr = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_TCP;
    iphdr->src_addr = sip;
    iphdr->dst_addr = dip;

    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    // 3 tcphdr
    struct rte_tcp_hdr* tcphdr = (struct rte_tcp_hdr*)(
        msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );
    tcphdr->src_port = frag->sport;
    tcphdr->dst_port = frag->dport;
    tcphdr->sent_seq = htonl(frag->seqnum);
    tcphdr->recv_ack = htonl(frag->acknum);

    tcphdr->data_off = frag->hdrlen_off;
    tcphdr->rx_win = frag->windows;
    tcphdr->tcp_urp = frag->tcp_urp;
    tcphdr->tcp_flags = frag->tcp_flags;

    if (frag->data != NULL) {
        uint8_t* data = (uint8_t*)(tcphdr+1) + frag->optlen * sizeof(uint32_t);
        rte_memcpy(data, frag->data, frag->data_len);
    }

    tcphdr->cksum = 0;
    tcphdr->cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);

    return 0;
}

struct rte_mbuf* make_tcp_pkt(uint32_t sip, uint32_t dip,
    uint8_t* smac, uint8_t* dmac, struct tcp_fragment* frag)
{
    const unsigned total_len =
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
        sizeof(struct rte_tcp_hdr) + frag->optlen* sizeof(uint32_t) +
        frag->data_len;

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(get_server_mempool());
    if (!mbuf) {
        printf("make_tcp_pkt failed\n");
        rte_exit(EXIT_FAILURE, "make_tcp_pkt rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t* pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_tcp_pkt(pktdata, sip, dip, smac, dmac, frag);

    return mbuf;
}