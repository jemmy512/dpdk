#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <rte_malloc.h>

#include "tcp.h"
#include "file.h"
#include "list.h"
#include "hash.h"
#include "socket.h"
#include "context.h"

static struct rte_hash* sock_table = NULL;

void init_sock_table(void) {
    sock_table = make_sock_table("sock hash table");
}

struct rte_hash* get_sock_table(void) {
    return sock_table;
}

void sock_add(struct sock* sk) {
    // list_add(sk, sock_table);
    struct sock_key key = {
        .sip = sk->sip,
        .dip = sk->dip,
        .sport = sk->sport,
        .dport = sk->dport,
        .protocol = sk->protocol
    };
    printf("sock add, ");
    print_key(&key);

    hash_add(get_sock_table(), &key, sk);
}

void sock_rm(struct sock* sk) {
    // list_rm(sk, get_sock_table());
    struct sock_key key = {
        .sip = sk->sip,
        .dip = sk->dip,
        .sport = sk->sport,
        .dport = sk->dport,
        .protocol = sk->protocol
    };
    hash_rm(get_sock_table(), &key);
}

static struct sock* get_sock(rte_be32_t sip, rte_be32_t dip, rte_be16_t sport, rte_be16_t dport, uint8_t protocol) {
    if (protocol == IPPROTO_UDP)
        return NULL;

    struct sock_key key = {
        .sip = sip,
        .dip = dip,
        .sport = sport,
        .dport = dport,
        .protocol = protocol
    };
    printf("get sock, ");
    print_key(&key);

    return hash_find(get_sock_table(), &key);
}

struct sock* get_tcp_sock(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    return get_sock(sip, dip, sport, dport, IPPROTO_TCP);

    // for (struct sock* sk = get_sock_table(); sk != NULL; sk = sk->next) {
    //     if (sk->sip == sip && sk->dip == dip && sk->sport == sport && sk->dport == dport) {
    //         sock = sk;
    //         break;
    //     }
    // }
}

struct sock* get_udp_sock(uint32_t sip, uint16_t sport) {
    return get_sock(sip, 0, sport, 0, IPPROTO_UDP);

    // for (struct sock* sk = get_sock_table(); sk != NULL; sk = sk->next) {
    //     if (dip == sk->sip && port == sk->sport && proto == sk->protocol) {
    //         sock = sk;
    //         break;
    //     }
    // }
}

struct sock* get_accept_sock(struct sock* listensk) {
    struct sock* sk = NULL;

    // for (struct sock* sk = get_sock_table(); sk != NULL; sk = sk->next) {
    //     if (port == sk->dport && sk->fd == -1) {
    //         sock = sk;
    //         break;
    //     }
    // }

    if (!LIST_EMPTY(&listensk->accept_head)) {
        sk = LIST_FIRST(&listensk->accept_head);
        LIST_REMOVE(sk, accept_entry);
    }

    return sk;
}

int add_accept_sock(struct sock* listensk, struct sock *sk) {
    LIST_INSERT_HEAD(&listensk->accept_head, sk, accept_entry);
    return 0;
}

struct sock* get_listen_sock(uint32_t sip, uint16_t sport) {
    return get_sock(sip, 0, sport, 0, IPPROTO_TCP);
    // struct sock* sock = NULL;

    // for (struct sock* sk = get_sock_table(); sk != NULL; sk = sk->next) {
    //     if (sk->sport == port && sk->status == TCP_STATUS_LISTEN) {
    //         sock = sk;
    //         break;
    //     }
    // }

    // return sock;
}

int net_socket(UN_USED int domain, int type, UN_USED uint8_t protocol) {
    struct sock* sk = NULL;
    int fd = get_fd();
    if (fd == -1)
        return fd;

    if (type == SOCK_DGRAM) {
        sk = rte_malloc("udp sock", sizeof(struct sock), 0);
        if (sk == NULL) {
           goto put_fd;
        }
        memset(sk, 0, sizeof(struct sock));

        sk->protocol = IPPROTO_UDP;

        char rcv_name[32] = { 0 };
        snprintf(rcv_name, 32, "udp rcv ring %d", fd);
        sk->rcvbuf = rte_ring_create(rcv_name, RING_SIZE, rte_socket_id(), 0);
        if (sk->rcvbuf == NULL) {
            rte_free(sk);
            goto put_fd;
        }

        char snd_name[32] = { 0 };
        snprintf(snd_name, 32, "udp snd ring %d", fd);
        sk->sndbuf = rte_ring_create(snd_name, RING_SIZE, rte_socket_id(), 0 );
        if (sk->sndbuf == NULL) {
            rte_ring_free(sk->rcvbuf);
            rte_free(sk);
            goto put_fd;
        }
    } else if (type == SOCK_STREAM) {
        sk = rte_malloc("tcp sock", sizeof(struct sock), 0);
        if (sk == NULL) {
            goto put_fd;
        }
        memset(sk, 0, sizeof(struct sock));

        sk->protocol = IPPROTO_TCP;
    }

    sk->fd = fd;
    set_fd(fd, sk);

    pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&sk->cond, &init_cond, sizeof(pthread_cond_t));

    pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&sk->mutex, &init_mutex, sizeof(pthread_mutex_t));

    return fd;

put_fd:
    put_fd(fd);

    return -1;
}

int net_bind(int sockfd, const struct sockaddr* addr, UN_USED socklen_t addrlen) {
    struct sock* sk = find_fd(sockfd);
    if (sk == NULL)
        return -1;

    const struct sockaddr_in* laddr = (const struct sockaddr_in*)addr;
    sk->sport = laddr->sin_port;
    rte_memcpy(&sk->sip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(sk->smac, get_local_mac(), RTE_ETHER_ADDR_LEN);

    if (sk->protocol == IPPROTO_TCP) {
        sk->status = TCP_STATUS_CLOSED;
    }

    sock_add(sk);

    return 0;
}

int net_listen(int sockfd, UN_USED int backlog) {
    struct sock* sk = find_fd(sockfd);
    if (sk == NULL)
        return -1;

    if (sk->protocol == IPPROTO_TCP) {
        sk->status = TCP_STATUS_LISTEN;
    }

    return 0;
}

int net_accept(int sockfd, struct sockaddr* addr, UN_USED socklen_t* addrlen) {
    struct sock* sk = find_fd(sockfd);
    if (sk == NULL)
        return -1;

    if (sk->protocol == IPPROTO_TCP) {
        struct sock* acpt = NULL;

        pthread_mutex_lock(&sk->mutex);
        while((acpt = get_accept_sock(sk)) == NULL) {
            pthread_cond_wait(&sk->cond, &sk->mutex);
        }
        pthread_mutex_unlock(&sk->mutex);

        // distinguish syn_rcvd sk and established sk
        acpt->fd = get_fd();
        set_fd(acpt->fd, acpt);

        struct sockaddr_in* saddr = (struct sockaddr_in*)addr;
        saddr->sin_port = acpt->sport;
        rte_memcpy(&saddr->sin_addr.s_addr, &acpt->sip, sizeof(uint32_t));

        return acpt->fd;
    }

    return -1;
}

ssize_t net_send(int sockfd, const void* buf, size_t len, UN_USED int flags) {
    ssize_t length = 0;

    struct sock* sk = find_fd(sockfd);
    if (sk == NULL)
        return -1;

    if (sk->protocol == IPPROTO_TCP) {
        struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (frag == NULL) {
            return -2;
        }

        memset(frag, 0, sizeof(struct tcp_fragment));

        frag->dport = sk->sport;
        frag->sport = sk->dport;

        frag->acknum = sk->rcv_nxt;
        frag->seqnum = sk->snd_nxt;

        frag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
        frag->windows = TCP_INITIAL_WINDOW;
        frag->hdrlen_off = 0x50;

        frag->data = rte_malloc("unsigned char*", len+1, 0);
        if (frag->data == NULL) {
            rte_free(frag);
            return -1;
        }
        memset(frag->data, 0, len+1);

        rte_memcpy(frag->data, buf, len);
        frag->data_len = len;
        length = frag->data_len;

        rte_ring_mp_enqueue(sk->sndbuf, frag);
    }

    return length;
}

ssize_t net_recv(int sockfd, void* buf, size_t len, UN_USED int flags) {
    ssize_t length = 0;

    struct sock* sk = find_fd(sockfd);
    if (sk == NULL)
        return -1;

    if (sk->protocol == IPPROTO_TCP) {
        struct tcp_fragment* frag = NULL;

        pthread_mutex_lock(&sk->mutex);
        while (rte_ring_mc_dequeue(sk->rcvbuf, (void**)&frag) < 0) {
            pthread_cond_wait(&sk->cond, &sk->mutex);
        }
        pthread_mutex_unlock(&sk->mutex);

        if (frag->data_len > len) {
            rte_memcpy(buf, frag->data, len);

            for (uint32_t i = 0; i < frag->data_len - len; ++i) {
                frag->data[i] = frag->data[len+i];
            }
            rte_memcpy(frag->data, &frag->data[len], frag->data_len-len);

            frag->data_len = frag->data_len-len;
            length = frag->data_len;

            rte_ring_mp_enqueue(sk->rcvbuf, frag);
        } else if (frag->data_len == 0) {
            rte_free(frag);
            return 0;
        } else {
            rte_memcpy(buf, frag->data, frag->data_len);
            length = frag->data_len;

            rte_free(frag->data);
            frag->data = NULL;

            rte_free(frag);
        }
    }

    return length;
}

ssize_t net_recvfrom(
    int sockfd, void* buf, size_t len, UN_USED int flags,
    struct sockaddr* src_addr, UN_USED socklen_t* addrlen)
{
    struct sock* sk = find_fd(sockfd);
    if (sk == NULL)
        return -1;

    struct offload* ol = NULL;
    unsigned char* data = NULL;

    struct sockaddr_in* saddr = (struct sockaddr_in*)src_addr;

    pthread_mutex_lock(&sk->mutex);
    while (rte_ring_mc_dequeue(sk->rcvbuf, (void**)&ol) < 0) {
        pthread_cond_wait(&sk->cond, &sk->mutex);
    }
    pthread_mutex_unlock(&sk->mutex);

    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

    if (len < ol->data_len) {
        rte_memcpy(buf, ol->data, len);

        data = rte_malloc("unsigned char* ", ol->data_len-len, 0);
        rte_memcpy(data, ol->data+len, ol->data_len-len);

        ol->data_len -= len;
        rte_free(ol->data);
        ol->data = data;

        rte_ring_mp_enqueue(sk->rcvbuf, ol);
    } else {
        len = ol->data_len;
        rte_memcpy(buf, ol->data, len);

        rte_free(ol->data);
        rte_free(ol);
    }

    return len;
}

ssize_t net_sendto(
    int sockfd, const void* buf, size_t len, UN_USED int flags,
    const struct sockaddr* dst_addr, UN_USED socklen_t addrlen)
{
    struct sock* sk = find_fd(sockfd);
    if (sk == NULL)
        return -1;

    const struct sockaddr_in* daddr = (const struct sockaddr_in*)dst_addr;

    struct offload* ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL)
        return -1;

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = sk->sip;
    ol->sport = sk->sport;
    ol->data_len = len;

    // struct in_addr addr;
    // addr.s_addr = ol->dip;
    // printf("net_sendto ---> src [%s:%d], data: %s\n", inet_ntoa(addr), ntohs(ol->dport), (const char*)buf);

    ol->data = rte_malloc("unsigned char* ", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);
    rte_ring_mp_enqueue(sk->sndbuf, ol);

    return len;
}

int net_close(int fd) {
    struct sock* sk = find_fd(fd);
    if (sk == NULL)
        return -1;

    if (sk->protocol == IPPROTO_UDP) {
        if (sk->rcvbuf) {
            rte_ring_free(sk->rcvbuf);
        }
        if (sk->sndbuf) {
            rte_ring_free(sk->sndbuf);
        }
    } else if (sk->protocol == IPPROTO_TCP) {
        if (sk->status != TCP_STATUS_LISTEN) {
            struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
            if (frag == NULL)
                return -1;
            memset(frag, 0, sizeof(struct tcp_fragment));

            frag->data = NULL;
            frag->data_len = 0;
            frag->sport = sk->dport;
            frag->dport = sk->sport;

            frag->seqnum = sk->snd_nxt;
            frag->acknum = sk->rcv_nxt;

            frag->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
            frag->windows = TCP_INITIAL_WINDOW;
            frag->hdrlen_off = 0x50;

            rte_ring_mp_enqueue(sk->sndbuf, frag);
            sk->status = TCP_STATUS_LAST_ACK;
        }
    }

    sock_rm(sk);
    put_fd(fd);

    return 0;
}

void print_key(struct sock_key* sk) {
    debug_ip_port("sk key", sk->sip, sk->dip, sk->sport, sk->dport, sk->protocol);
}

void debug_ip_port(const char* name, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t protocol) {
    struct in_addr saddr;
    saddr.s_addr = sip;
    printf("%s --- src: %s:%d", name, inet_ntoa(saddr), ntohs(sport));

    struct in_addr daddr;
    daddr.s_addr = dip;
    printf(", dst: %s:%d, protocol: %d\n", inet_ntoa(daddr), ntohs(dport), protocol);
}