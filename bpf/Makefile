CLANG = clang

EXECABLE = monitor-exec

BPFCODE = bpf_program
BPFTOOLS = /home/king/share/ubuntu-bionic/samples/bpf
# BPFLOADER = $(BPFTOOLS)/bpf_load.c
# CCINCLUDE += -I/home/king/share/ubuntu-bionic/tools/testing/selftests/bpf

# LOADINCLUDE += -I/home/king/share/ubuntu-bionic/samples/bpf
# LOADINCLUDE += -I/home/king/share/ubuntu-bionic/tools/lib

# LOADINCLUDE += -I/home/king/share/ubuntu-bionic/tools/perf
# LOADINCLUDE += -I/home/king/share/ubuntu-bionic/tools/include
LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbpf

.PHONY: clean $(CLANG) bpfload build

clean:
	rm -f *.o *.so $(EXECABLE)

build: ${BPFCODE.c} ${BPFLOADER}
	$(CLANG) -O2 -target bpf -c $(BPFCODE:=.c) $(CCINCLUDE) -o ${BPFCODE:=.o}
bpfload: build
	clang -o $(EXECABLE) -lelf $(LOADINCLUDE) $(LIBRARY_PATH) $(BPFSO) $(BPFLOADER) loader.c
$(EXECABLE): bpfload

.DEFAULT_GOAL := $(EXECABLE)

export ARCH=x86