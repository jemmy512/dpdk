#include "arp.h"

#include <arpa/inet.h>

#include <rte_arp.h>
#include <rte_malloc.h>

#include "context.h"

#define TIMER_RESOLUTION_CYCLES 60000000000ULL // 10ms * 1000 = 10s * 6

#define ARP_REQ_IP MAKE_IPV4_ADDR(192, 168, 4, 234)

static struct arp_table* arp_table_ins = NULL;

uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static struct rte_timer arp_timer;

static void print_ip_mac(const char* name, uint32_t ip, uint8_t* mac) {
    struct in_addr addr;
    addr.s_addr = ip;

    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, (struct rte_ether_addr*)mac);

    printf("%s --> ip: %s, mac: %s\n", name, inet_ntoa(addr), buf);
}

struct arp_table* get_arp_table(void) {
    if (arp_table_ins == NULL) {
        arp_table_ins = rte_malloc("arp table", sizeof(struct  arp_table), 0);
        if (arp_table_ins == NULL) {
            rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
        }
        memset(arp_table_ins, 0, sizeof(struct arp_table));
        pthread_spin_init(&arp_table_ins->lock, PTHREAD_PROCESS_SHARED);
    }

    return arp_table_ins;
}

uint8_t* get_arp_mac(uint32_t dst_ip) {
    struct arp_table* table = get_arp_table();

    pthread_spin_lock(&table->lock);
    int count = table->count;
    for (struct arp_entry* iter = table->entries; --count > 0 && iter != NULL; iter = iter->next) {
        if (dst_ip == iter->ip) {
            pthread_spin_unlock(&table->lock);
            return iter->mac;
        }
    }
    pthread_spin_unlock(&table->lock);

    return NULL;
}

int arp_table_add(uint32_t ip, uint8_t* mac, uint8_t type) {
    if (get_arp_mac(ip) == NULL) {
        struct arp_entry* entry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
        if (entry) {
            memset(entry, 0, sizeof(struct arp_entry));

            entry->ip = ip;
            rte_memcpy(entry->mac, mac, RTE_ETHER_ADDR_LEN);
            entry->type = type;

            struct arp_table* table = get_arp_table();

            pthread_spin_lock(&table->lock);
            list_add(entry, table->entries);
            ++table->count;
            pthread_spin_unlock(&table->lock);

            // print_ip_mac("arp entry add", entry->ip, entry->mac);

            return 1;
        }
    }

    return 0;
}

int arp_table_rm(uint32_t ip) {
    int ret = 1;
    struct arp_table* table = get_arp_table();

    pthread_spin_lock(&table->lock);
    for (struct arp_entry* iter = table->entries; iter != NULL; iter = iter->next) {
        if (ip == iter->ip) {
            --table->count;
            list_rm(iter, table->entries);
            ret = 0;
            break;
        }
    }
    pthread_spin_unlock(&table->lock);

    return ret;
}

int encode_arp_pkt(uint8_t* msg, uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip) {
    // 1 ethhdr
    struct rte_ether_hdr* eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, get_local_mac(), RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // 2 arp
    struct rte_arp_hdr* arp = (struct rte_arp_hdr*)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(opcode);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, get_local_mac(), RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}

struct rte_mbuf* make_arp_mbuf(uint16_t opcode, uint8_t* dst_mac, uint32_t sip, uint32_t dip) {
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(get_server_mempool());
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
    encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

    return mbuf;
}

void debug_arp_table(void) {
    struct arp_table* table = get_arp_table();

    pthread_spin_lock(&table->lock);
    for (struct arp_entry* iter = table->entries; iter != NULL; iter = iter->next) {
        print_ip_mac("arp entry", iter->ip, iter->mac);
    }
    pthread_spin_unlock(&table->lock);
}

 void arp_pkt_handler(struct rte_mbuf* mbuf) {
    struct rte_arp_hdr* arphdr = rte_pktmbuf_mtod_offset(
        mbuf, struct rte_arp_hdr* , sizeof(struct rte_ether_hdr)
    );

    if (arphdr->arp_data.arp_tip == get_local_ip()) {
        if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
            printf("arp --> recv req\n");

            struct rte_mbuf* arpbuf = make_arp_mbuf(
                RTE_ARP_OP_REPLY,
                arphdr->arp_data.arp_sha.addr_bytes,
                arphdr->arp_data.arp_tip,
                arphdr->arp_data.arp_sip
            );

            struct inout_ring* ring = get_server_ring();
            rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
        } else if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
            printf("arp --> recv reply\n");

            uint8_t* mac = get_arp_mac(arphdr->arp_data.arp_sip);

            if (mac == NULL) {
                arp_table_add(arphdr->arp_data.arp_sip, arphdr->arp_data.arp_sha.addr_bytes, 0);
            }

            // debug_arp_table();
        }
    }
}

void arp_timer_tick(void) {
    static uint64_t prev_tsc = 0, cur_tsc;
    cur_tsc = rte_rdtsc();

    if (cur_tsc - prev_tsc > TIMER_RESOLUTION_CYCLES) {
        rte_timer_manage();
        prev_tsc = cur_tsc;
    }
}

void init_arp_timer(void) {
    rte_timer_subsystem_init();

    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, NULL);
}

void arp_request_timer_cb(UN_USED struct rte_timer* timer, UN_USED void* arg) {
    uint32_t arp_req_ip = ARP_REQ_IP;

    for (int i = 233; i <= 235; ++i) {
        uint32_t dstip = (arp_req_ip & 0x00FFFFFF) | (0xFF000000 & (i << 24));

        struct in_addr addr;
        addr.s_addr = dstip;
        printf("arp ping ---> src: %s \n", inet_ntoa(addr));

        struct rte_mbuf* arpbuf = NULL;
        uint8_t* dst_mac = get_arp_mac(dstip);

        if (dst_mac == NULL) {
            arpbuf = make_arp_mbuf(RTE_ARP_OP_REQUEST, gDefaultArpMac, get_local_ip(), dstip);
        } else {
            arpbuf = make_arp_mbuf(RTE_ARP_OP_REQUEST, dst_mac, get_local_ip(), dstip);
        }

        struct inout_ring *ring = get_server_ring();
        rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
    }
}