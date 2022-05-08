#include "tcp.h"

#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_hash.h>

#include "list.h"
#include "socket.h"
#include "arp.h"
#include "context.h"
#include "file.h"
#include "epoll.h"
#include "config.h"


#define BUFFER_SIZE	1024

#define Server_Port 9999

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

    struct sock* sk = get_tcp_sock(
        iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port
    );
    if (sk == NULL) {
        sk = get_listen_sock(iphdr->dst_addr, tcphdr->dst_port);
    }
    if (sk == NULL) {
        return -2;
    }

    switch (sk->status) {
        case TCP_STATUS_CLOSED:
            break;

        case TCP_STATUS_LISTEN:
            tcp_handle_listen(sk, tcphdr, iphdr);
            break;

        case TCP_STATUS_SYN_RCVD:
            tcp_handle_syn_rcvd(sk, tcphdr);
            break;

        case TCP_STATUS_SYN_SENT:
            break;

        case TCP_STATUS_ESTABLISHED: {
            int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
            tcp_handle_established(sk, tcphdr, tcplen);
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
            tcp_handle_close_wait(sk, tcphdr);
            break;

        case TCP_STATUS_LAST_ACK:
            tcp_handle_last_ack(sk, tcphdr);
            break;
    }

    printf("tcp_pkt_handler done\n");

    return 0;
}

struct sock* tcp_sock_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    struct sock* sk = rte_malloc("tcp sock", sizeof(struct sock), 0);
    if (sk == NULL)
        return NULL;
    memset(sk, 0, sizeof(struct sock));

    sk->sip = sip;
    sk->dip = dip;
    sk->sport = sport;
    sk->dport = dport;
    sk->protocol = IPPROTO_TCP;
    sk->fd = -1; // unused

    sk->status = TCP_STATUS_CLOSED;

    struct in_addr saddr;
    saddr.s_addr = sip;
    char* src_ip = inet_ntoa(saddr);
    uint16_t src_port = ntohs(sport);

    char buf_name[32] = {0};

    snprintf(buf_name, 32, "tcpsnd%s:%d", src_ip, src_port);
    sk->sndbuf = rte_ring_create(buf_name, RING_SIZE, rte_socket_id(), 0);
    printf("%s\n", buf_name);

    snprintf(buf_name, 32, "tcprcv%s:%d", src_ip, src_port);
    sk->rcvbuf = rte_ring_create(buf_name, RING_SIZE, rte_socket_id(), 0);
    printf("%s\n", buf_name);

    uint32_t next_seed = time(NULL);
    sk->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
    rte_memcpy(sk->smac, get_local_mac(), RTE_ETHER_ADDR_LEN);

    pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&sk->cond, &init_cond, sizeof(pthread_cond_t));

    pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&sk->mutex, &init_mutex, sizeof(pthread_mutex_t));

    return sk;
}

int tcp_handle_listen(struct sock* sk, struct rte_tcp_hdr* tcphdr, struct rte_ipv4_hdr* iphdr) {
    if ((tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) == 0)
        return -1;

    if (sk->status != TCP_STATUS_LISTEN)
        return -1;

    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG && sk->status == TCP_STATUS_LISTEN) {
        struct sock* syn_sk = tcp_sock_create(
            iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port
        );
        sock_add(syn_sk);

        struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (frag == NULL)
            return -1;
        memset(frag, 0, sizeof(struct tcp_fragment));

        frag->sport = tcphdr->dst_port;
        frag->dport = tcphdr->src_port;

        frag->seqnum = syn_sk->snd_nxt;
        frag->acknum = ntohl(tcphdr->sent_seq) + 1;
        syn_sk->rcv_nxt = frag->acknum;

        frag->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
        frag->windows = TCP_INITIAL_WINDOW;
        frag->hdrlen_off = 0x50;

        frag->data = NULL;
        frag->data_len = 0;

        rte_ring_mp_enqueue(syn_sk->sndbuf, frag);

        syn_sk->status = TCP_STATUS_SYN_RCVD;
    }

    return 0;
}

int tcp_handle_syn_rcvd(struct sock* sk, struct rte_tcp_hdr* tcphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG && sk->status == TCP_STATUS_SYN_RCVD) {
        uint32_t acknum = ntohl(tcphdr->recv_ack);
        if (acknum == sk->snd_nxt + 1) {

        }

        sk->status = TCP_STATUS_ESTABLISHED;

        // accept
        struct sock* listener = get_listen_sock(sk->dip, sk->dport);
        if (listener == NULL) {
            rte_exit(EXIT_FAILURE, "get_listen_sock failed\n");
        }

        pthread_mutex_lock(&listener->mutex);
        pthread_cond_signal(&listener->cond);
        pthread_mutex_unlock(&listener->mutex);

        epoll_callback(get_epoll(), listener->fd, EPOLLIN);
    }

    return 0;
}

int tcp_handle_established(struct sock* sk, struct rte_tcp_hdr* tcphdr, int tcplen) {
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
        rte_ring_mp_enqueue(sk->rcvbuf, rfragment);
#else

        tcp_enqueue_rcvbuf(sk, tcphdr, tcplen);

#endif

#if 0
        // ack pkt
        struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (frag == NULL) return -1;
        memset(frag, 0, sizeof(struct tcp_fragment));

        frag->dport = tcphdr->src_port;
        frag->sport = tcphdr->dst_port;

        // remote

        printf("tcp_handle_established: %d, %d\n", sk->rcv_nxt, ntohs(tcphdr->sent_seq));


        sk->rcv_nxt = sk->rcv_nxt + data_len;
        // local
        sk->snd_nxt = ntohl(tcphdr->recv_ack);
        //frag->

        frag->acknum = sk->rcv_nxt;
        frag->seqnum = sk->snd_nxt;

        frag->tcp_flags = RTE_TCP_ACK_FLAG;
        frag->windows = TCP_INITIAL_WINDOW;
        frag->hdrlen_off = 0x50;
        frag->data = NULL;
        frag->length = 0;

        rte_ring_mp_enqueue(sk->sndbuf, frag);

#else

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int data_len = tcplen - hdrlen * 4;

        sk->rcv_nxt = sk->rcv_nxt + data_len;
        sk->snd_nxt = ntohl(tcphdr->recv_ack);

        tcp_send_ack(sk, tcphdr);

#endif
        // echo pkt
#if 0
        struct tcp_fragment* echofrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (echofrag == NULL) return -1;
        memset(echofrag, 0, sizeof(struct tcp_fragment));

        echofrag->dport = tcphdr->src_port;
        echofrag->sport = tcphdr->dst_port;

        echofrag->acknum = sk->rcv_nxt;
        echofrag->seqnum = sk->snd_nxt;

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

        rte_ring_mp_enqueue(sk->sndbuf, echofrag);
#endif
    }

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

    }

    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

        sk->status = TCP_STATUS_CLOSE_WAIT;
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

        rte_ring_mp_enqueue(sk->rcvbuf, rfragment);

#else
        tcp_enqueue_rcvbuf(sk, tcphdr, tcphdr->data_off >> 4);

#endif
        // send ack ptk
        sk->rcv_nxt = sk->rcv_nxt + 1;
        sk->snd_nxt = ntohl(tcphdr->recv_ack);

        tcp_send_ack(sk, tcphdr);
    }

    return 0;
}

int tcp_handle_close_wait(struct sock* sk, struct rte_tcp_hdr* tcphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG && sk->status == TCP_STATUS_CLOSE_WAIT) {

    }

    return 0;
}

int tcp_handle_last_ack(struct sock* sk, struct rte_tcp_hdr* tcphdr) {
    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG && sk->status == TCP_STATUS_LAST_ACK) {
        sk->status = TCP_STATUS_CLOSED;

        sock_rm(sk);

        if (sk->sndbuf) {
            rte_ring_free(sk->sndbuf);
        }
        if (sk->rcvbuf) {
            rte_ring_free(sk->rcvbuf);
        }

        rte_free(sk);
    }

    return 0;
}

int tcp_send_ack(struct sock* sk, struct rte_tcp_hdr* tcphdr) {
    struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
    if (frag == NULL)
        return -1;
    memset(frag, 0, sizeof(struct tcp_fragment));

    frag->dport = tcphdr->src_port;
    frag->sport = tcphdr->dst_port;

    // remote
    printf("tcp_send_ack: %d, %d\n", sk->rcv_nxt, ntohs(tcphdr->sent_seq));

    frag->acknum = sk->rcv_nxt;
    frag->seqnum = sk->snd_nxt;

    frag->tcp_flags = RTE_TCP_ACK_FLAG;
    frag->windows = TCP_INITIAL_WINDOW;
    frag->hdrlen_off = 0x50;
    frag->data = NULL;
    frag->data_len = 0;

    rte_ring_mp_enqueue(sk->sndbuf, frag);

    return 0;
}

int tcp_enqueue_rcvbuf(struct sock* sk, struct rte_tcp_hdr* tcphdr, int tcplen) {
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
    rte_ring_mp_enqueue(sk->rcvbuf, frag);

    // notify net_recv
    pthread_mutex_lock(&sk->mutex);
    pthread_cond_signal(&sk->cond);
    pthread_mutex_unlock(&sk->mutex);

    epoll_callback(get_epoll(), sk->fd, EPOLLIN);

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
    servaddr.sin_addr.s_addr = local_ip;
    servaddr.sin_port = htons(Server_Port);
    net_bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    net_listen(listenfd, 10);

    int epfd = nepoll_create(1);
    struct epoll_event ev, events[128];
    ev.events = EPOLLIN;
    ev.data.fd = listenfd;
    nepoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);

    char buff[BUFFER_SIZE] = {0};
    while (1) {
        printf("epoll going to sleep\n");
        int nb_ready = nepoll_wait(epfd, events, 128, -1);
        printf("epoll wake up, %d\n", nb_ready);

        for (int i = 0; i < nb_ready; ++i) {
            if (listenfd == events[i].data.fd) {
                struct sockaddr_in client;
                socklen_t len = sizeof(client);
                int connfd = net_accept(listenfd, (struct sockaddr*)&client, &len);

                struct epoll_event ev;
                ev.events = EPOLLIN;
                ev.data.fd = connfd;
                nepoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
            } else {
                int connfd = events[i].data.fd;

                int nb_rx = net_recv(connfd, buff, BUFFER_SIZE, 0);
                if (nb_rx > 0) {
                    printf("rcv: %s\n", buff);
                    net_send(connfd, buff, nb_rx, 0);
                } else {
                    nepoll_ctl(epfd, EPOLL_CTL_DEL, connfd, NULL);
                    net_close(connfd);
                }
            }
        }
    }

    net_close(listenfd);
}

int tcp_server_out(void) {
    struct net_key* key = NULL;
	struct sock* sk = NULL;
	uint32_t next = 0;

	while (rte_hash_iterate(get_sock_table(), (const void**)&key, (void**)&sk, &next) >= 0) {
        if (sk->sndbuf == NULL || sk->protocol != IPPROTO_TCP)
            continue; // listener

        struct tcp_fragment* frag = NULL;
        int nb_snd = rte_ring_mc_dequeue(sk->sndbuf, (void**)&frag);
        if (nb_snd < 0)
            continue;

        // printf("tcp_server_out... count: %d\n", table->count);

        uint8_t* dmac = get_arp_mac(sk->sip);
        if (dmac == NULL) {
            struct rte_mbuf* arpbuf = make_arp_mbuf(
                RTE_ARP_OP_REQUEST, gDefaultArpMac, sk->dip, sk->sip
            );

            struct inout_ring* ring = get_server_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
            rte_ring_mp_enqueue(sk->sndbuf, frag);
        } else {
            struct rte_mbuf* tcpbuf = make_tcp_pkt(
                sk->dip, sk->sip, sk->smac, dmac, frag
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