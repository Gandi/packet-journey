# Packet-journey, linux router based on DPDK

The purpose of this project is to provide an application capable of:
* Switching many packets using the LPM algorithm
* Make this switching scalable with the possibility of adding more packet queues/CPUs
* Learning routes from the Linux kernel using Netlink
* Learning neighbors from Netlink, the kernel is refreshing them automatically
* Being able to forward some packets to the kernel which will handle them (ARP, ICMP, BGP)
* Rate limit ICMP packets that are sent to the kernel
* Permit adding L3/L4 ACLs
* Permit gathering statistics and managing ACLs through a cli based on a unixsock
* Make all those things configurable through a configfile
* Make it free

Most of these features are based on various DPDK libs.
