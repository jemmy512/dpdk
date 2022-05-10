
#include "util.h"

#include <stdio.h>

void print_hex(const uint8_t* buf, size_t len) {
    printf("%zu bytes:\n", len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", buf[i]);
    }
    printf("\n");
}