#include "epoll.h"

#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_memcpy.h>

#include "file.h"

static struct eventpoll* g_epoll = NULL;

static int sockfd_cmp(struct epitem *ep1, struct epitem *ep2) {
    if (ep1->sockfd < ep2->sockfd)
        return -1;
    else
        if (ep1->sockfd == ep2->sockfd)
            return 0;

    return 1;
}

RB_GENERATE_STATIC(_epoll_rb_socket, epitem, rb_node, sockfd_cmp);

int nepoll_create(int size) {
    if (size <= 0)
        return -1;

    int epfd = get_fd();

    struct eventpoll *ep = (struct eventpoll*)rte_malloc("eventpoll", sizeof(struct eventpoll), 0);
    if (!ep) {
        put_fd(epfd);
        return -1;
    }

    ep->fd = epfd;
    ep->rbcnt = 0;
    RB_INIT(&ep->rbr);
    LIST_INIT(&ep->rdlist);

    if (pthread_mutex_init(&ep->mtx, NULL)) {
        rte_free(ep);
        put_fd(epfd);
        return -2;
    }

    if (pthread_mutex_init(&ep->event_mtx, NULL)) {
        pthread_mutex_destroy(&ep->mtx);
        rte_free(ep);
        put_fd(epfd);
        return -2;
    }

    if (pthread_cond_init(&ep->event_cond, NULL)) {
        pthread_mutex_destroy(&ep->event_mtx);
        pthread_mutex_destroy(&ep->mtx);
        rte_free(ep);
        put_fd(epfd);
        return -2;
    }

    if (pthread_spin_init(&ep->lock, PTHREAD_PROCESS_SHARED)) {
        pthread_cond_destroy(&ep->event_cond);
        pthread_mutex_destroy(&ep->event_mtx);
        pthread_mutex_destroy(&ep->mtx);
        rte_free(ep);

        put_fd(epfd);
        return -2;
    }

    set_fd(epfd, ep);

    g_epoll = ep;

    return epfd;
}

int nepoll_ctl(int epfd, int op, int sockId, struct epoll_event *event) {
    struct eventpoll *ep = (struct eventpoll*)find_fd(epfd);
    if (!ep || (!event && op != EPOLL_CTL_DEL)) {
        rte_errno = -EINVAL;
        return -1;
    }

    struct epitem item;
    item.sockfd = sockId;

    if (op == EPOLL_CTL_ADD) {
        pthread_mutex_lock(&ep->mtx);

        struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &item);
        if (epi) {
            pthread_mutex_unlock(&ep->mtx);
            return -1;
        }

        epi = (struct epitem*)rte_malloc("epitem", sizeof(struct epitem), 0);
        if (!epi) {
            pthread_mutex_unlock(&ep->mtx);
            rte_errno = -ENOMEM;
            return -1;
        }

        epi->sockfd = sockId;
        rte_memcpy(&epi->event, event, sizeof(struct epoll_event));

        epi = RB_INSERT(_epoll_rb_socket, &ep->rbr, epi);

        ep->rbcnt++;

        pthread_mutex_unlock(&ep->mtx);

    } else if (op == EPOLL_CTL_DEL) {
        pthread_mutex_lock(&ep->mtx);
        struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &item);
        if (!epi) {
            pthread_mutex_unlock(&ep->mtx);
            return -1;
        }

        epi = RB_REMOVE(_epoll_rb_socket, &ep->rbr, epi);
        if (!epi) {
            pthread_mutex_unlock(&ep->mtx);
            return -1;
        }

        ep->rbcnt--;
        rte_free(epi);

        pthread_mutex_unlock(&ep->mtx);

    } else if (op == EPOLL_CTL_MOD) {
        struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &item);
        if (epi) {
            epi->event.events = event->events;
            epi->event.events |= EPOLLERR | EPOLLHUP;
        } else {
            rte_errno = -ENOENT;
            return -1;
        }
    }

    return 0;
}

int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    struct eventpoll *ep = (struct eventpoll*)find_fd(epfd);
    if (!ep || !events || maxevents <= 0) {
        rte_errno = -EINVAL;
        return -1;
    }

    if (pthread_mutex_lock(&ep->event_mtx)) {
        if (rte_errno == EDEADLK) {
            printf("epoll lock blocked\n");
        }
    }

    while (ep->rdnum == 0 && timeout != 0) {
        ep->waiting = 1;
        if (timeout > 0) {
            struct timespec deadline;

            clock_gettime(CLOCK_REALTIME, &deadline);
            if (timeout >= 1000) {
                int sec;
                sec = timeout / 1000;
                deadline.tv_sec += sec;
                timeout -= sec * 1000;
            }

            deadline.tv_nsec += timeout * 1000000;

            if (deadline.tv_nsec >= 1000000000) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000;
            }

            int ret = pthread_cond_timedwait(&ep->event_cond, &ep->event_mtx, &deadline);
            if (ret && ret != ETIMEDOUT) {
                printf("pthread_cond_timewait\n");

                pthread_mutex_unlock(&ep->event_mtx);

                return -1;
            }
            timeout = 0;

        } else if (timeout < 0) {
            int ret = pthread_cond_wait(&ep->event_cond, &ep->event_mtx);
            if (ret) {
                printf("pthread_cond_wait\n");
                pthread_mutex_unlock(&ep->event_mtx);

                return -1;
            }
        }
        ep->waiting = 0;
    }

    pthread_mutex_unlock(&ep->event_mtx);

    pthread_spin_lock(&ep->lock);

    int cnt = 0;
    int num = (ep->rdnum > maxevents ? maxevents : ep->rdnum);
    int i = 0;

    while (num != 0 && !LIST_EMPTY(&ep->rdlist)) {
        struct epitem *epi = LIST_FIRST(&ep->rdlist);
        LIST_REMOVE(epi, rdlink);
        epi->in_rdlist = 0;

        rte_memcpy(&events[i++], &epi->event, sizeof(struct epoll_event));

        num--;
        cnt++;
        ep->rdnum--;
    }

    pthread_spin_unlock(&ep->lock);

    return cnt;
}

int epoll_callback(struct eventpoll *ep, int sockid, uint32_t event) {
    struct epitem item;
    item.sockfd = sockid;

    struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &item);
    if (!epi) {
        printf("rbtree not exist\n");
        return -1;
    }
    if (epi->in_rdlist) {
        epi->event.events |= event;
        return 1;
    }

    printf("epoll_callback --> %d\n", epi->sockfd);

    pthread_spin_lock(&ep->lock);
    epi->in_rdlist = 1;
    LIST_INSERT_HEAD(&ep->rdlist, epi, rdlink);
    ep->rdnum++;
    pthread_spin_unlock(&ep->lock);

    pthread_mutex_lock(&ep->event_mtx);
    pthread_cond_signal(&ep->event_cond);
    pthread_mutex_unlock(&ep->event_mtx);

    return 0;
}

struct eventpoll* get_epoll(void) {
    return g_epoll;
}