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

static struct tcp_table* tcp_table_ins = NULL;

struct tcp_table* get_tcp_table(void) {
    if (tcp_table_ins == NULL) {
        tcp_table_ins = rte_malloc("tcp_table", sizeof(struct tcp_table), 0);
        memset(tcp_table_ins, 0, sizeof(struct tcp_table));
    }
    return tcp_table_ins;
}

int tcp_pkt_handler(struct rte_mbuf* tcpmbuf) {
    struct rte_ipv4_hdr* iphdr =  rte_pktmbuf_mtod_offset(
        tcpmbuf, struct rte_ipv4_hdr* , sizeof(struct rte_ether_hdr)
    );
    struct rte_tcp_hdr* tcphdr = (struct rte_tcp_hdr*)(iphdr + 1);

    // tcphdr, rte_ipv4_udptcp_cksum
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

    stream->sip = sip;
    stream->dip = dip;
    stream->sport = sport;
    stream->dport = dport;
    stream->protocol = IPPROTO_TCP;
    stream->fd = -1; //unused

    stream->status = TCP_STATUS_LISTEN;

    printf("tcp_stream_create\n");

    stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
    stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);

    uint32_t next_seed = time(NULL);
    stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
    rte_memcpy(stream->localmac, get_local_mac(), RTE_ETHER_ADDR_LEN);

    pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &init_cond, sizeof(pthread_cond_t));

    pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &init_mutex, sizeof(pthread_mutex_t));

    //struct tcp_table* table = get_tcp_table();
    //list_add(stream, table->tcb_set);

    return stream;
}

int tcp_handle_listen(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, struct rte_ipv4_hdr* iphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG && stream->status == TCP_STATUS_LISTEN) {
        struct tcp_table* table = get_tcp_table();
        struct tcp_stream* syn_stream = tcp_stream_create(
            iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port
        );
        list_add(syn_stream, table->tcb_set);

        struct tcp_fragment* fragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (fragment == NULL)
            return -1;
        memset(fragment, 0, sizeof(struct tcp_fragment));

        fragment->sport = tcphdr->dst_port;
        fragment->dport = tcphdr->src_port;

        fragment->seqnum = syn_stream->snd_nxt;
        fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
        syn_stream->rcv_nxt = fragment->acknum;

        fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
        fragment->windows = TCP_INITIAL_WINDOW;
        fragment->hdrlen_off = 0x50;

        fragment->data = NULL;
        fragment->data_len = 0;

        rte_ring_mp_enqueue(syn_stream->sndbuf, fragment);

        syn_stream->status = TCP_STATUS_SYN_RCVD;
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

int tcp_enqueue_recvbuffer(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr, int tcplen) {
    struct tcp_fragment* fragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
    if (fragment == NULL)
        return -1;
    memset(fragment, 0, sizeof(struct tcp_fragment));

    fragment->dport = ntohs(tcphdr->dst_port);
    fragment->sport = ntohs(tcphdr->src_port);

    uint8_t hdrlen = tcphdr->data_off >> 4;
    int payloadlen = tcplen - hdrlen * 4;
    if (payloadlen > 0) {
        uint8_t* payload = (uint8_t*)tcphdr + hdrlen* 4;
        fragment->data = rte_malloc("unsigned char* ", payloadlen+1, 0);
        if (fragment->data == NULL) {
            rte_free(fragment);
            return -1;
        }
        memset(fragment->data, 0, payloadlen+1);
        rte_memcpy(fragment->data, payload, payloadlen);
        fragment->data_len = payloadlen;
    } else if (payloadlen == 0) {
        fragment->data_len = 0;
        fragment->data = NULL;
    }
    rte_ring_mp_enqueue(stream->rcvbuf, fragment);

    // notify net_recv
    pthread_mutex_lock(&stream->mutex);
    pthread_cond_signal(&stream->cond);
    pthread_mutex_unlock(&stream->mutex);

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
        int payloadlen = tcplen - hdrlen* 4;
        if (payloadlen > 0) {

            uint8_t* payload = (uint8_t*)tcphdr + hdrlen* 4;

            rfragment->data = rte_malloc("unsigned char* ", payloadlen+1, 0);
            if (rfragment->data == NULL) {
                rte_free(rfragment);
                return -1;
            }
            memset(rfragment->data, 0, payloadlen+1);

            rte_memcpy(rfragment->data, payload, payloadlen);
            rfragment->length = payloadlen;

            printf("tcp : %s\n", rfragment->data);
        }
        rte_ring_mp_enqueue(stream->rcvbuf, rfragment);
#else

        tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);

#endif


#if 0
        // ack pkt
        struct tcp_fragment* ackfrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (ackfrag == NULL) return -1;
        memset(ackfrag, 0, sizeof(struct tcp_fragment));

        ackfrag->dport = tcphdr->src_port;
        ackfrag->sport = tcphdr->dst_port;

        // remote

        printf("tcp_handle_established: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));


        stream->rcv_nxt = stream->rcv_nxt + payloadlen;
        // local
        stream->snd_nxt = ntohl(tcphdr->recv_ack);
        //ackfrag->

        ackfrag->acknum = stream->rcv_nxt;
        ackfrag->seqnum = stream->snd_nxt;

        ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
        ackfrag->windows = TCP_INITIAL_WINDOW;
        ackfrag->hdrlen_off = 0x50;
        ackfrag->data = NULL;
        ackfrag->length = 0;

        rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

#else

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payloadlen = tcplen - hdrlen* 4;

        stream->rcv_nxt = stream->rcv_nxt + payloadlen;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        tcp_send_ackpkt(stream, tcphdr);

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

        uint8_t* payload = (uint8_t*)tcphdr + hdrlen* 4;

        echofrag->data = rte_malloc("unsigned char* ", payloadlen, 0);
        if (echofrag->data == NULL) {
            rte_free(echofrag);
            return -1;
        }
        memset(echofrag->data, 0, payloadlen);

        rte_memcpy(echofrag->data, payload, payloadlen);
        echofrag->length = payloadlen;

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
        int payloadlen = tcplen - hdrlen* 4;

        rfragment->length = 0;
        rfragment->data = NULL;

        rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

#else
        tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);

#endif
        // send ack ptk
        stream->rcv_nxt = stream->rcv_nxt + 1;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        tcp_send_ackpkt(stream, tcphdr);

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

        struct tcp_table* table = get_tcp_table();
        list_rm(stream, table->tcb_set);

        rte_ring_free(stream->sndbuf);
        rte_ring_free(stream->rcvbuf);

        rte_free(stream);
    }

    return 0;
}

int tcp_send_ackpkt(struct tcp_stream* stream, struct rte_tcp_hdr* tcphdr) {

    struct tcp_fragment* ackfrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
    if (ackfrag == NULL)
        return -1;
    memset(ackfrag, 0, sizeof(struct tcp_fragment));

    ackfrag->dport = tcphdr->src_port;
    ackfrag->sport = tcphdr->dst_port;

    // remote
    printf("tcp_send_ackpkt: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));

    ackfrag->acknum = stream->rcv_nxt;
    ackfrag->seqnum = stream->snd_nxt;

    ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
    ackfrag->windows = TCP_INITIAL_WINDOW;
    ackfrag->hdrlen_off = 0x50;
    ackfrag->data = NULL;
    ackfrag->data_len = 0;

    rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

    return 0;
}

int main_tcp_server(__attribute__((unused))  void* arg)  {
    int listenfd = net_socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1) {
        return -1;
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(struct sockaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(9999);
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

        struct tcp_fragment* fragment = NULL;
        int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment);
        if (nb_snd < 0)
            continue;

        uint8_t* dstmac = get_arp_mac(stream->sip);
        if (dstmac == NULL) {
            struct rte_mbuf* arpbuf = make_arp_mbuf(
                RTE_ARP_OP_REQUEST, gDefaultArpMac, stream->dip, stream->sip
            );

            struct inout_ring* ring = get_server_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
            rte_ring_mp_enqueue(stream->sndbuf, fragment);
        } else {
            struct rte_mbuf* tcpbuf = make_tcp_pkt(
                stream->dip, stream->sip, stream->localmac, dstmac, fragment
            );
            struct inout_ring* ring = get_server_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&tcpbuf, 1, NULL);

            if (fragment->data != NULL)
                rte_free(fragment->data);

            rte_free(fragment);
        }
    }

    return 0;
}

int encode_tcp_pkt(uint8_t* msg, uint32_t sip, uint32_t dip,
    uint8_t* srcmac, uint8_t* dstmac, struct tcp_fragment* fragment)
{
    const unsigned total_len =
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
        sizeof(struct rte_tcp_hdr) + fragment->optlen * sizeof(uint32_t) +
        fragment->data_len;

    // 1 ethhdr
    struct rte_ether_hdr* eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2 iphdr
    struct rte_ipv4_hdr* ip = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = sip;
    ip->dst_addr = dip;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3 tcphdr
    struct rte_tcp_hdr* tcphdr = (struct rte_tcp_hdr*)(
        msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
    );
    tcphdr->src_port = fragment->sport;
    tcphdr->dst_port = fragment->dport;
    tcphdr->sent_seq = htonl(fragment->seqnum);
    tcphdr->recv_ack = htonl(fragment->acknum);

    tcphdr->data_off = fragment->hdrlen_off;
    tcphdr->rx_win = fragment->windows;
    tcphdr->tcp_urp = fragment->tcp_urp;
    tcphdr->tcp_flags = fragment->tcp_flags;

    if (fragment->data != NULL) {
        uint8_t* payload = (uint8_t*)(tcphdr+1) + fragment->optlen * sizeof(uint32_t);
        rte_memcpy(payload, fragment->data, fragment->data_len);
    }

    tcphdr->cksum = 0;
    tcphdr->cksum = rte_ipv4_udptcp_cksum(ip, tcphdr);

    return 0;
}

struct rte_mbuf* make_tcp_pkt(uint32_t sip, uint32_t dip,
    uint8_t* srcmac, uint8_t* dstmac, struct tcp_fragment* fragment)
{
    const unsigned total_len =
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
        sizeof(struct rte_tcp_hdr) + fragment->optlen* sizeof(uint32_t) +
        fragment->data_len;

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(get_server_mempool());
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t* pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_tcp_pkt(pktdata, sip, dip, srcmac, dstmac, fragment);

    return mbuf;
}