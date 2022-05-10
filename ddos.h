
#include <rte_mbuf.h>

#define CAPTURE_WINDOWS        256

int ddos_detect(struct rte_mbuf* pkt);