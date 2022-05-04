#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <rte_malloc.h>

#include "socket.h"
#include "list.h"
#include "tcp.h"
#include "file.h"
#include "context.h"

struct localhost* host_table = NULL;
pthread_spinlock_t host_table_lock = PTHREAD_PROCESS_SHARED;

static uint64_t ring_id = 0;

int net_socket(UN_USED int domain, int type, UN_USED int protocol) {
    int fd = get_fd();
    if (fd == -1)
        return fd;

    if (type == SOCK_DGRAM) {
        struct localhost* host = rte_malloc("localhost", sizeof(struct localhost), 0);
        if (host == NULL) {
           goto put_fd;
        }
        memset(host, 0, sizeof(struct localhost));

        host->fd = fd;
        host->protocol = IPPROTO_UDP;

        char rcv_name[64];
        snprintf(rcv_name, 64, "udp rcv ring %d", ring_id);
        printf("ring name 1: %s\n", rcv_name);
        host->rcvbuf = rte_ring_create(rcv_name, RING_SIZE, rte_socket_id(), 0);
        if (host->rcvbuf == NULL) {
            rte_free(host);
            goto put_fd;
        }

        char snd_name[64];
        snprintf(snd_name, 64, "udp snd ring %d", ring_id++);
        printf("ring name 2: %s\n", snd_name);
        host->sndbuf = rte_ring_create(snd_name, RING_SIZE, rte_socket_id(), 0 );
        if (host->sndbuf == NULL) {
            rte_ring_free(host->rcvbuf);
            rte_free(host);
            goto put_fd;
        }

        pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&host->cond, &init_cond, sizeof(pthread_cond_t));

        pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&host->mutex, &init_mutex, sizeof(pthread_mutex_t));

        pthread_spin_lock(&host_table_lock);
        list_add(host, host_table);
        pthread_spin_unlock(&host_table_lock);
    } else if (type == SOCK_STREAM) {
        struct tcp_stream* stream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
        if (stream == NULL) {
            goto put_fd;
        }
        memset(stream, 0, sizeof(struct tcp_stream));

        stream->fd = fd;
        stream->protocol = IPPROTO_TCP;
        stream->next = stream->prev = NULL;

        pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&stream->cond, &init_cond, sizeof(pthread_cond_t));

        pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&stream->mutex, &init_mutex, sizeof(pthread_mutex_t));

        tcp_table_add(stream);
    }

    return fd;

put_fd:
    put_fd(fd);

    return -1;
}

int net_bind(int sockfd, const struct sockaddr* addr, UN_USED socklen_t addrlen) {
    void* hostinfo =  get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL)
        return -1;

    struct localhost* host = (struct localhost*)hostinfo;

    if (host->protocol == IPPROTO_UDP) {
        const struct sockaddr_in* laddr = (const struct sockaddr_in*)addr;
        host->localport = laddr->sin_port;
        rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        rte_memcpy(host->localmac, get_local_mac(), RTE_ETHER_ADDR_LEN);
    } else if (host->protocol == IPPROTO_TCP) {
        struct tcp_stream* stream = (struct tcp_stream*)hostinfo;
        const struct sockaddr_in* laddr = (const struct sockaddr_in*)addr;
        stream->dport = laddr->sin_port;
        rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        rte_memcpy(stream->localmac, get_local_mac(), RTE_ETHER_ADDR_LEN);

        stream->status = TCP_STATUS_CLOSED;
    }

    return 0;
}

int net_listen(int sockfd, UN_USED int backlog) {
    void* hostinfo = get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL)
        return -1;

    struct tcp_stream* stream = (struct tcp_stream*)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        stream->status = TCP_STATUS_LISTEN;
    }

    return 0;
}

int net_accept(int sockfd, struct sockaddr* addr, UN_USED socklen_t* addrlen) {
    void* hostinfo =  get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL)
        return -1;

    struct tcp_stream* stream = (struct tcp_stream*)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        struct tcp_stream* acpt = NULL;

        pthread_mutex_lock(&stream->mutex);
        while((acpt = get_accept_stream(stream->dport)) == NULL) {
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }
        pthread_mutex_unlock(&stream->mutex);

        // distinguish syn_rcvd stream and established stream
        acpt->fd = get_fd();

        struct sockaddr_in* saddr = (struct sockaddr_in*)addr;
        saddr->sin_port = acpt->sport;
        rte_memcpy(&saddr->sin_addr.s_addr, &acpt->sip, sizeof(uint32_t));

        return acpt->fd;
    }

    return -1;
}

ssize_t net_send(int sockfd, const void* buf, size_t len, UN_USED int flags) {
    ssize_t length = 0;

    void* hostinfo = get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL)
        return -1;

    struct tcp_stream* stream = (struct tcp_stream*)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (frag == NULL) {
            return -2;
        }

        memset(frag, 0, sizeof(struct tcp_fragment));

        frag->dport = stream->sport;
        frag->sport = stream->dport;

        frag->acknum = stream->rcv_nxt;
        frag->seqnum = stream->snd_nxt;

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

        rte_ring_mp_enqueue(stream->sndbuf, frag);
    }

    return length;
}

ssize_t net_recv(int sockfd, void* buf, size_t len, UN_USED int flags) {
    ssize_t length = 0;

    void* hostinfo = get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL)
        return -1;

    struct tcp_stream* stream = (struct tcp_stream*)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        struct tcp_fragment* frag = NULL;

        pthread_mutex_lock(&stream->mutex);
        while (rte_ring_mc_dequeue(stream->rcvbuf, (void**)&frag) < 0) {
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }
        pthread_mutex_unlock(&stream->mutex);

        if (frag->data_len > len) {
            rte_memcpy(buf, frag->data, len);

            for (uint32_t i = 0; i < frag->data_len - len; ++i) {
                frag->data[i] = frag->data[len+i];
            }
            // rte_memcpy(frag->data, &frag->data[len], frag->data_len-len);

            frag->data_len = frag->data_len-len;
            length = frag->data_len;

            rte_ring_mp_enqueue(stream->rcvbuf, frag);
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
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL)
        return -1;

    struct offload* ol = NULL;
    unsigned char* data = NULL;

    struct sockaddr_in* saddr = (struct sockaddr_in*)src_addr;

    pthread_mutex_lock(&host->mutex);
    while (rte_ring_mc_dequeue(host->rcvbuf, (void**)&ol) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);

    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

    if (len < ol->data_len) {
        rte_memcpy(buf, ol->data, len);

        data = rte_malloc("unsigned char* ", ol->data_len-len, 0);
        rte_memcpy(data, ol->data+len, ol->data_len-len);

        ol->data_len -= len;
        rte_free(ol->data);
        ol->data = data;

        rte_ring_mp_enqueue(host->rcvbuf, ol);
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
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL)
        return -1;

    const struct sockaddr_in* daddr = (const struct sockaddr_in*)dst_addr;

    struct offload* ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL)
        return -1;

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->localip;
    ol->sport = host->localport;
    ol->data_len = len;

    struct in_addr addr;
    addr.s_addr = ol->dip;
    // printf("net_sendto ---> src [%s:%d], data: %s\n", inet_ntoa(addr), ntohs(ol->dport), (const char*)buf);

    ol->data = rte_malloc("unsigned char* ", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);
    rte_ring_mp_enqueue(host->sndbuf, ol);

    return len;
}

int net_close(int fd) {
    void* hostinfo =  get_hostinfo_by_fd(fd);
    if (hostinfo == NULL)
        return -1;

    struct localhost* host = (struct localhost*)hostinfo;
    if (host->protocol == IPPROTO_UDP) {
        hostinfo_rm(host);

        if (host->rcvbuf) {
            rte_ring_free(host->rcvbuf);
        }
        if (host->sndbuf) {
            rte_ring_free(host->sndbuf);
        }

        rte_free(host);

        put_fd(fd);

    } else if (host->protocol == IPPROTO_TCP) {
        struct tcp_stream* stream = (struct tcp_stream*)hostinfo;

        if (stream->status != TCP_STATUS_LISTEN) {
            struct tcp_fragment* frag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
            if (frag == NULL)
                return -1;
            memset(frag, 0, sizeof(struct tcp_fragment));

            frag->data = NULL;
            frag->data_len = 0;
            frag->sport = stream->dport;
            frag->dport = stream->sport;

            frag->seqnum = stream->snd_nxt;
            frag->acknum = stream->rcv_nxt;

            frag->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
            frag->windows = TCP_INITIAL_WINDOW;
            frag->hdrlen_off = 0x50;

            rte_ring_mp_enqueue(stream->sndbuf, frag);
            stream->status = TCP_STATUS_LAST_ACK;

            put_fd(fd);
        } else {
            tcp_table_rm(stream);

            rte_free(stream);
        }
    }

    return 0;
}

void* get_hostinfo_by_fd(int sockfd) {
    void* ret = NULL;

    pthread_spin_lock(&host_table_lock);
    for (struct localhost* host = host_table; host != NULL; host = host->next) {
        if (sockfd == host->fd) {
            ret = (void*)host;
            break;
        }
    }
    pthread_spin_unlock(&host_table_lock);

    if (ret)
        return ret;

    struct tcp_stream* stream = NULL;
    struct tcp_table* table = get_tcp_table();

    for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
        if (sockfd == stream->fd) {
            return stream;
        }
    }

    return NULL;
}

struct localhost* get_hostinfo_by_ip_port(uint32_t dip, uint16_t port, uint8_t proto) {
    pthread_spin_lock(&host_table_lock);
    for (struct localhost* host = host_table; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport && proto == host->protocol) {
            pthread_spin_unlock(&host_table_lock);
            return host;
        }
    }
    pthread_spin_unlock(&host_table_lock);

    return NULL;
}

void hostinfo_rm(struct localhost* host) {
    pthread_spin_lock(&host_table_lock);
    list_rm(host, host_table);
    pthread_spin_unlock(&host_table_lock);
}

void debug_ip_port(const char* name, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    struct in_addr addr;
    addr.s_addr = sip;
    printf("%s ---> src: %s:%d", name, inet_ntoa(addr), ntohs(sport));

    addr.s_addr = dip;
    printf(", dst: %s:%d \n", inet_ntoa(addr), ntohs(dport));
}