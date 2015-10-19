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

## Internals

### Threads

Packet-journey (pktj) is composed of multiple kind of threads :
* pktj, the main thread which is doing all the initialization and are handling signals.
* forward-LCOREID, those threads are doing the forwarding part. They are reading packets from the PMD, doing the processing of those packets and sending them back to the PMD.
* kni-LCOREID, those threads are reading packets from the KNI and sending them to the configured port.
* lcore-slave-LCOREID, those threads are doing nothing, they are just waiting.
* control-SOCKETID, those threads are in charge of receiving NETLINK messages from the IFADDR, ROUTE, NEIGH and LINK groups and handling them.
* cmdline-SOCKETID, those threads are presenting a CLI through the unixsocks.
* rdtsc-SOCKETID, those threads are reading the TSC value and exposing it to the lcore-slave threads.

For optimal performances, the forwarding threads must be alone on their cores. All other threads can be scheduled on the same lcore.

### Processing steps

The forwarding threads are running the main_loop() function. It can be resumed by those steps:
1. read up to 32 packet descriptors
2. if none, read again
3. prepare the acl processing for the new packets and filter them
4. find the correct neighbor for the remaining packets by looking into the ipv4 or ipv6 LPM
5. if a packet has no possible next_hop in the LPM or if a packet has the router IP, send it to the kni and remove it from the rest of the processing loop
6. for each remaining packets, set the correct destination MAC address according to the selected next_hop
7. reorder packets by destination port
8. send the packets in batch grouped by destination port

## Configuration examples

```pktj -l 0,1,2,3 -n 4 --socket-mem=4096 --log-level=4 -- --configfile /root/devel/router-dpdk/tests/integration/lab00/pktj.conf```

with pktj.conf containing :
```
; pktj
[pktj]
callback-setup  = /root/devel/router-dpdk/tests/integration/lab00/up.sh
rule_ipv4       = /root/devel/router-dpdk/tests/integration/lab00/acl.txt
rule_ipv6       = /root/devel/router-dpdk/tests/integration/lab00/acl6.txt
promiscuous     = 1
kni_rate_limit  = 1000
aclavx2         = 1

; Port configuration
[port 0]
eal queues      = 0,1 1,2 ; queue,lcore
kni             = 3,0 ; lcore_tx,kthread
```

Those settings will launch pktj with 2 forwarding threads, on core 1 and 2, a KNI tx thread on core 3, will launch the script ```up.sh``` after setting up the KNI.
