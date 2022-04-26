#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <rte_malloc.h>

#include "socket.h"
#include "list.h"

extern struct localhost* lhost;
extern uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

#define DEFAULT_FD_NUM 3

int get_fd_frombitmap(void) {
    int fd = DEFAULT_FD_NUM;
    return fd;
}

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol) {
    const int fd = get_fd_frombitmap();

    struct localhost* host = rte_malloc("localhost", sizeof(struct localhost), 0);
    if (host == NULL) {
        return -1;
    }
    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;

    if (type == SOCK_DGRAM)
        host->protocol = IPPROTO_UDP;
    else if (type == SOCK_STREAM)
        host->protocol = IPPROTO_TCP;

    host->rcvbuf = rte_ring_create("rcv buffer", RING_SIZE, rte_socket_id(), 0);
    if (host->rcvbuf == NULL) {
        rte_free(host);
        return -1;
    }

    host->sndbuf = rte_ring_create("snd buffer", RING_SIZE, rte_socket_id(), 0);
    if (host->sndbuf == NULL) {
        rte_ring_free(host->rcvbuf);
        rte_free(host);
        return -1;
    }

    pthread_cond_t init_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &init_cond, sizeof(pthread_cond_t));

    pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &init_mutex, sizeof(pthread_mutex_t));

    list_add(host, lhost);

    return fd;
}

int nbind(int sockfd, const struct sockaddr* addr, __attribute__((unused)) socklen_t addrlen) {
    struct localhost* host = get_hostinfo_by_fd(sockfd);
    if (host == NULL)
        return -1;

    const struct sockaddr_in* laddr = (const struct sockaddr_in*)addr;
    host->localport = laddr->sin_port;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    return 0;
}

ssize_t nrecvfrom(
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

ssize_t nsendto(
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
    printf("nsendto ---> src [%s:%d], data: %s", inet_ntoa(addr), ntohs(ol->dport), (const char*)buf);

    ol->data = rte_malloc("unsigned char* ", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);

    rte_ring_mp_enqueue(host->sndbuf, ol);

    return len;
}

int nclose(int fd) {
    struct localhost* host = get_hostinfo_by_fd(fd);
    if (host == NULL) {
        return -1;
    }

    list_rm(host, lhost);

    if (host->rcvbuf) {
        rte_ring_free(host->rcvbuf);
    }
    if (host->sndbuf) {
        rte_ring_free(host->sndbuf);
    }

    rte_free(host);

    return 0;
}