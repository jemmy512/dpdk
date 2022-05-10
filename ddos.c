
#include "ddos.h"

#include <stdint.h>
#include <math.h>

/* hping3 -c 1200 -d 120 -S -w 64 -p 9999 --flood --rand-source 192.168.4.94 */

#define CAPTURE_WINDOWS        256

static double threashold = 1200.0;

static uint32_t one_bits[CAPTURE_WINDOWS] = {0};
static uint32_t tot_bits[CAPTURE_WINDOWS] = {0};
static double entropy_set[CAPTURE_WINDOWS] = {0};
static int pkt_idx = 0;

static double ddos_entropy(double set_bits, double total_bits);

static uint32_t count_bit(uint8_t* msg, const uint32_t length);

static double ddos_entropy(double set_bits, double total_bits) {
    return ( - set_bits) * (log2(set_bits) - log2(total_bits)) // 1
    - (total_bits - set_bits) * (log2(total_bits - set_bits) - log2(total_bits))
    + log2(total_bits);
}


static uint32_t count_bit(uint8_t* msg, const uint32_t length) {

#if 0
    uint32_t v; // count bits set in this (32-bit value)
    uint32_t c, set_bits = 0; // store the total here
    static const int S[5] = {1, 2, 4, 8, 16}; // Magic Binary Numbers
    static const int B[5] = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};

    uint32_t* ptr = (uint32_t*)msg;
    uint32_t* end = (uint32_t*)msg + length;

    while (ptr < end) {
        v =* ptr++;

        c = v - ((v >> S[0]) & B[0]);
        c = ((c >> S[1]) & B[1]) + (c & B[1]);
        c = ((c >> S[2]) + c) & B[2];
        c = ((c >> S[3]) + c) & B[3];
        c = ((c >> S[4]) + c) & B[4];

        set_bits += c;
    }
#else

    uint64_t v, set_bits = 0;
    const uint64_t* ptr = (uint64_t*) msg;
    const uint64_t* end = (uint64_t*) (msg + length);

    do {
      v = *(ptr++);
      v = v - ((v >> 1) & 0x5555555555555555); // reuse input as temporary
      v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333); // temp
      v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0F;
      set_bits += (v * 0x0101010101010101) >> (sizeof(v) - 1) * 8; // count

    } while(ptr < end);

#endif

    return set_bits;
}


int ddos_detect(struct rte_mbuf* pkt) {
    static char flag = 0; // 1 ddos, 0 no attack

    uint8_t* msg = rte_pktmbuf_mtod(pkt, uint8_t*);
    uint32_t bit_one = count_bit(msg, pkt->buf_len);

    uint32_t bit_count = pkt->buf_len * 8;

    one_bits[pkt_idx % CAPTURE_WINDOWS] = bit_one;
    tot_bits[pkt_idx % CAPTURE_WINDOWS] = bit_count;
    entropy_set[pkt_idx % CAPTURE_WINDOWS] = ddos_entropy(bit_one, bit_count);

    //printf("\n %u/%u, E(%f)\n", bit_one, bit_count, entropy_set[pkt_idx % CAPTURE_WINDOWS]);
    if (pkt_idx >= CAPTURE_WINDOWS) {

        int i = 0;
        uint32_t total_set = 0, total_bit = 0;
        double sum_entropy = 0.0;

        for (i = 0;i < CAPTURE_WINDOWS;i ++) {
            total_set += one_bits[i]; // set_bits
            total_bit += tot_bits[i]; // count_bits
            sum_entropy += entropy_set[i];
        }

        double entropy = ddos_entropy(total_set, total_bit);

        printf("%u/%u Entropy(%f), Total_Entropy(%f)\n", total_set, total_bit, sum_entropy, entropy);

        if (threashold <  sum_entropy - entropy) {
            if (!flag) {
                // printf("ddos attack !!! Entropy(%f) < Total_Entropy(%f)\n", entropy, sum_entropy);
                rte_exit(EXIT_FAILURE, "ddos attack !!! Entropy(%f) < Total_Entropy(%f)\n", entropy, sum_entropy);
                return 1;
            }
            flag = 1;
        } else {
            if (flag) {
                printf( "no new !!! Entropy(%f) < Total_Entropy(%f)\n", entropy, sum_entropy);
            }

            flag = 0;
        }

        // sum(entropy_set[i])
        // ddos_entropy(sum(set_bits), sum(tot_bits));

        pkt_idx = (pkt_idx+1) % CAPTURE_WINDOWS + CAPTURE_WINDOWS;
    } else {
        pkt_idx ++;
    }

    return 0;
}
