#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_kni.h>

struct rte_kni* get_kni(void);

int is_fwd_to_kni(struct rte_ether_hdr* ehdr);

struct rte_kni* alloc_kni(void);

void init_kni(void);

void kni_out(void);