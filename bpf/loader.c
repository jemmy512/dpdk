#include "bpf_load.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (load_bpf_file("bpf_program.o") != 0) {
        printf("Load BPF faile faield\n")
        return -1;
    }

    read_trace_pipe();

    return 0;
}