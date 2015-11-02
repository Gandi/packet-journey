# How to launch the QEMU test environment

## Requirements

- DPDK 2.1.0
- Linux kernel source (>= 4.1 if DPDK >= 2.1)
- QEMU KVM >= 2.2
- brctl (from bridge-utils)
- Debian multistrap

## Compilation

1. Compile a Linux kernel with the provided config file (```config```)
2. Copy the bzImage file from ```arch/x86_64/boot/``` to this folder (```integration```)
3. Export the RTE_KERNELDIR environment variable, it should contain the path to the kernel package (for instance: ```/home/pktj/linux-4.1.7/```)
4. Compile DPDK
5. Compile pktj with BUILD_TARGET=qemu (```make BUILD_TARGET=qemu```)

## First run

1. Export RTE_SDK and RTE_TARGET environment variables (it should be already done if you have compiled pktj successfully)
2. Run the lab with:
```
./lab.sh
```
3. Connect to VMs using the output from the previous command
4. pktj is now ready to start on r2, you can use the sample configuration file in ```/mnt/build/conf/pktj.conf```
and start the app with a command such as:
```
/mnt/build/build/app/$RTE_TARGET/pktj --log-level 8 -l 0,1,2,3 -n 1 -- --configfile /mnt/build/conf/pktj.conf
```

