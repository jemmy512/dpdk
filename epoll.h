#pragma once

#include <sys/queue.h>

#include <stdint.h>
#include <pthread.h>

#include "rb_tree.h"

enum EPOLL_EVENTS {
    EPOLLNONE   = 0x0000,
    EPOLLIN     = 0x0001,
    EPOLLPRI    = 0x0002,
    EPOLLOUT    = 0x0004,
    EPOLLRDNORM = 0x0040,
    EPOLLRDBAND = 0x0080,
    EPOLLWRNORM = 0x0100,
    EPOLLWRBAND = 0x0200,
    EPOLLMSG    = 0x0400,
    EPOLLERR    = 0x0008,
    EPOLLHUP     = 0x0010,
    EPOLLRDHUP     = 0x2000,
    EPOLLONESHOT = (1 << 30),
    EPOLLET     = (1 << 31)
};

#define EPOLL_CTL_ADD    1
#define EPOLL_CTL_DEL    2
#define EPOLL_CTL_MOD    3

typedef union epoll_data {
    void *ptr;
    int fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t events;
    epoll_data_t data;
};

struct epitem {
    RB_ENTRY(epitem) rb_node;
    LIST_ENTRY(epitem) rdlink;
    int in_rdlist;

	int wait_id;
    int sockfd;
    struct epoll_event event;
};

RB_HEAD(_epoll_rb_socket, epitem);

typedef struct _epoll_rb_socket ep_rb_tree;

struct eventpoll {
    int fd;

    ep_rb_tree rbr;
    int rbcnt;

    LIST_HEAD(, epitem) rdlist;
    int rdnum;

    int waiting;

    pthread_mutex_t mtx;
    pthread_spinlock_t lock;

    pthread_cond_t event_cond;
    pthread_mutex_t event_mtx;
};

struct eventpoll* get_epoll(void);

int nepoll_create(int size);
int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event);
int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);
int epoll_callback(struct eventpoll *ep, int sockid, uint32_t event);
