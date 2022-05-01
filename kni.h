#include <netinet/in.h>
#include <rte_ether.h>
#include <rte_kni.h>

struct rte_kni* get_kni(void);

int if_fwd_to_kni(struct rte_ether_hdr* ehdr);

int config_network_if(uint16_t port_id, uint8_t if_up);

struct rte_kni* alloc_kni(void);

void init_kni(void);

void kni_out(void);