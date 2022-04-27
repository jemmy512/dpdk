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

int net_socket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {
    int fd = get_fd_from_bitmap();

    if (type == SOCK_DGRAM) {
        struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
        if (host == NULL) {
           goto release_fd;
        }
        memset(host, 0, sizeof(struct localhost));

        host->fd = fd;
        host->protocol = IPPROTO_UDP;

        host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), 0);
        if (host->rcvbuf == NULL) {
            rte_free(host);
            goto release_fd;
        }

        host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), 0 );
        if (host->sndbuf == NULL) {
            rte_ring_free(host->rcvbuf);
            rte_free(host);
            goto release_fd;
        }

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        list_add(host, host_table);
    } else if (type == SOCK_STREAM) {
        struct tcp_stream *stream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
        if (stream == NULL) {
            goto release_fd;
        }
        memset(stream, 0, sizeof(struct tcp_stream));

        stream->fd = fd;
        stream->protocol = IPPROTO_TCP;
        stream->next = stream->prev = NULL;
        stream->rcvbuf = rte_ring_create("tcp recv buffer", RING_SIZE, rte_socket_id(), 0);
        if (stream->rcvbuf == NULL) {
            rte_free(stream);
            goto release_fd;
        }

        stream->sndbuf = rte_ring_create("tcp send buffer", RING_SIZE, rte_socket_id(), 0);
        if (stream->sndbuf == NULL) {
            rte_ring_free(stream->rcvbuf);
            rte_free(stream);
            goto release_fd;
        }

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        struct tcp_table *table = get_tcp_table();
        list_add(stream, table->tcb_set);
        // get_stream_from_fd();
    }

    return fd;

release_fd:
    set_fd_to_bitmap(fd);

    return -1;
}

int net_bind(int sockfd, const struct sockaddr* addr, __attribute__((unused)) socklen_t addrlen) {
	void *hostinfo =  get_hostinfo_by_fd(sockfd);
	if (hostinfo == NULL)
        return -1;

	struct localhost *host = (struct localhost *)hostinfo;

	if (host->protocol == IPPROTO_UDP) {
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		host->localport = laddr->sin_port;
		rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(host->localmac, get_local_mac(), RTE_ETHER_ADDR_LEN);

	} else if (host->protocol == IPPROTO_TCP) {

		struct tcp_stream *stream = (struct tcp_stream *)hostinfo;

		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		stream->dport = laddr->sin_port;
		rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(stream->localmac, get_local_mac(), RTE_ETHER_ADDR_LEN);

		stream->status = TCP_STATUS_CLOSED;

	}

	return 0;

}

ssize_t net_recvfrom(
    int sockfd, void* buf, size_t len, __attribute__((unused)) int flags,
    struct sockaddr* src_addr, __attribute__((unused)) socklen_t* addrlen)
{
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL) return -1;

    struct offload* ol = NULL;
    unsigned char* ptr = NULL;

    struct sockaddr_in* saddr = (struct sockaddr_in*)src_addr;

    int nb = -1;
    pthread_mutex_lock(&host->mutex);
    while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void**)&ol)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);

    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

    if (len < ol->length) {
        rte_memcpy(buf, ol->data, len);

        ptr = rte_malloc("unsigned char* ", ol->length-len, 0);
        rte_memcpy(ptr, ol->data+len, ol->length-len);

        ol->length -= len;
        rte_free(ol->data);
        ol->data = ptr;

        rte_ring_mp_enqueue(host->rcvbuf, ol);
    } else {
        len = ol->length;
        rte_memcpy(buf, ol->data, len);

        rte_free(ol->data);
        rte_free(ol);
    }

    return len;
}

ssize_t net_sendto(
    int sockfd, const void* buf, size_t len, __attribute__((unused)) int flags,
    const struct sockaddr* dest_addr, __attribute__((unused)) socklen_t addrlen)
{
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL)
        return -1;

    const struct sockaddr_in* daddr = (const struct sockaddr_in*)dest_addr;

    struct offload* ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL)
        return -1;

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->localip;
    ol->sport = host->localport;
    ol->length = len;

    struct in_addr addr;
    addr.s_addr = ol->dip;
    printf("net_sendto ---> src [%s:%d], data: %s", inet_ntoa(addr), ntohs(ol->dport), (const char*)buf);

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
    struct localhost* host = get_hostinfo_by_fd(fd);
    if (host == NULL) {
        return -1;
    }

    list_rm(host, host_table);

    if (host->rcvbuf) {
        rte_ring_free(host->rcvbuf);
    }
    if (host->sndbuf) {
        rte_ring_free(host->sndbuf);
    }

    rte_free(host);

    return 0;
}

int net_listen(int sockfd, __attribute__((unused)) int backlog) { //

    void *hostinfo =  get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL) return -1;


    struct tcp_stream *stream = (struct tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        stream->status = TCP_STATUS_LISTEN;
    }

    return 0;
}

int net_accept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {

    void *hostinfo =  get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL) return -1;

    struct tcp_stream *stream = (struct tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {

        struct tcp_stream *apt = NULL;

        pthread_mutex_lock(&stream->mutex);
        while((apt = get_accept_stream(stream->dport)) == NULL) {
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }
        pthread_mutex_unlock(&stream->mutex);

        apt->fd = get_fd_from_bitmap();

        struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
        saddr->sin_port = apt->sport;
        rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

        return apt->fd;
    }

    return -1;
}


ssize_t net_send(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags) {

    ssize_t length = 0;

    void *hostinfo =  get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL) return -1;

    struct tcp_stream *stream = (struct tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {

        struct tcp_fragment *fragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
        if (fragment == NULL) {
            return -2;
        }

        memset(fragment, 0, sizeof(struct tcp_fragment));

        fragment->dport = stream->sport;
        fragment->sport = stream->dport;

        fragment->acknum = stream->rcv_nxt;
        fragment->seqnum = stream->snd_nxt;

        fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
        fragment->windows = TCP_INITIAL_WINDOW;
        fragment->hdrlen_off = 0x50;


        fragment->data = rte_malloc("unsigned char *", len+1, 0);
        if (fragment->data == NULL) {
            rte_free(fragment);
            return -1;
        }
        memset(fragment->data, 0, len+1);

        rte_memcpy(fragment->data, buf, len);
        fragment->data_len = len;
        length = fragment->data_len;

        // int nb_snd = 0;
        rte_ring_mp_enqueue(stream->sndbuf, fragment);
    }

    return length;
}

// recv 32
// recv
ssize_t net_recv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
    ssize_t length = 0;

    void *hostinfo =  get_hostinfo_by_fd(sockfd);
    if (hostinfo == NULL)
        return -1;

    struct tcp_stream *stream = (struct tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        struct tcp_fragment *fragment = NULL;
        int nb_rcv = 0;

        pthread_mutex_lock(&stream->mutex);
        while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }
        pthread_mutex_unlock(&stream->mutex);

        if (fragment->data_len > len) {
            rte_memcpy(buf, fragment->data, len);


            for(uint32_t i = 0; i < fragment->data_len - len; i ++) {
                fragment->data[i] = fragment->data[len+i];
            }
            fragment->data_len = fragment->data_len-len;
            length = fragment->data_len;

            rte_ring_mp_enqueue(stream->rcvbuf, fragment);

        } else if (fragment->data_len == 0) {
            rte_free(fragment);
            return 0;
        } else {
            rte_memcpy(buf, fragment->data, fragment->data_len);
            length = fragment->data_len;

            rte_free(fragment->data);
            fragment->data = NULL;

            rte_free(fragment);
        }
    }

    return length;
}

void* get_hostinfo_by_fd(int sockfd) {
	for (struct localhost *host = host_table; host != NULL; host = host->next) {
		if (sockfd == host->fd) {
			return host;
		}
	}

	struct tcp_stream *stream = NULL;
	struct tcp_table *table = get_tcp_table();

	for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}

    return NULL;
}

struct localhost* get_hostinfo_by_ip_port(uint32_t dip, uint16_t port, uint8_t proto) {
    for (struct localhost* host = host_table; host != NULL; host = host->next) {
        if (dip == host->localip && port == host->localport && proto == host->protocol) {
            return host;
        }
    }

    return NULL;
}

void debug_ip_port(const char* name, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    struct in_addr addr;
    addr.s_addr = sip;
    printf("%s ---> src: %s:%d", name, inet_ntoa(addr), ntohs(sport));

    addr.s_addr = dip;
    printf(", dst: %s:%d \n", inet_ntoa(addr), ntohs(dport));
}