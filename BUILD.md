# Build instructions

## DPDK

For building DPDK, you may follow those instructions http://dpdk.org/doc/guides/linux_gsg/build_dpdk.html

## Normal binary
For building Packet-journey, you may just run `make`, default build settings are good enough.
You can use DPDK command line variables described here http://dpdk.org/doc/guides/prog_guide/ext_app_lib_make_help.html
You will find the generated apps here : build/app/build/pktj

## Developpement binary (for Qemu)
If you want to test your code or your environment setup, we have a build option for building Packet-journey for qemu `make RDPDK_QEMU=1`.
You may then test your code by launching the test environment by using test/integration/lab.sh

# Build Debian packages
You will need to build DPDK Debian packages using our debian/ files, you may find them here https://github.com/Gandi/dpdk-debian

Then just build Packet-journey the normal Debian way, for exemple `debuild -us -uc`
