# vmware fusion
* downalod
    * version: 12
    * https://www.vmware.com/go/getfusion
* config nic
    * set eth0 bridge connection
    * set eth1 NAT
    * change the default VM driver (e1000) to the vmxnet3
        * Virtual Machines.localized/Ubuntu desk 20.04.3.vmwarevm/Ubuntu desk 20.04.3.vmx
        * ethernet0.virtualDev = "vmxnet3"

# ubuntu
* downlaod
    * version: 20.04.4 LTS
    * https://ubuntu.com/download/desktop/thank-you?version=20.04.4&architecture=amd64

* check nic multi-queue support
    ```
    cat /proc/interrupts

    root@ubuntu:/code/dpdk-stable-19.11.12# cat /proc/interrupts
                CPU0       CPU1       CPU2       CPU3       CPU4       CPU5
    56:          0          0          0         74        532        640   PCI-MSI 1572864-edge      eth0-rxtx-0
    57:         18          0          0          0         17         36   PCI-MSI 1572865-edge      eth0-rxtx-1
    58:          0          0          0          5         51         14   PCI-MSI 1572866-edge      eth0-rxtx-2
    59:          0          0          0          0        280         10   PCI-MSI 1572867-edge      eth0-rxtx-3
    60:          0          0          0          0          0          0   PCI-MSI 1572868-edge      eth0-event-4
    ```

# dpdk
1. download
    * version: 19.11.12 LTS
    * https://fast.dpdk.org/rel/dpdk-19.11.12.tar.xz

2. compile
    * ./dpdk-stable-19.11.12/usertools/dpdk-setup.sh
    * [44] x86_64-native-linux-gcc

3. set enviroment variables
    ```
    /root/.bashrc

    export RTE_SDK=/code/dpdk-stable-19.11.12
    export RTE_TARGET=x86_64-native-linux-gcc
    ```

4. set hugepage
    * [51] Setup hugepage mappings for non-NUMA systems
        * Option: 51
        * Number of pages: 512
    * [52] Setup hugepage mappings for NUMA systems
        * Option: 52
        * Number of pages: 512

5. insert IGB_UIO VFIO model
    * [48] Insert IGB UIO module
    * [49] Insert VFIO module

6. bind igb_uio model
    * down eth0
        * ifconfig eth0 down
    * [54] Bind Ethernet/Baseband/Crypto device to IGB UIO module