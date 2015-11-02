# Packet-journey, linux router based on DPDK

The purpose of this project is to provide a **free** application capable of:

* Switching many packets using the LPM algorithm
* Making this switching scalable with the possibility of adding more packet queues/CPUs
* Learning routes from the Linux kernel using Netlink
* Learning neighbors from Netlink, the kernel is refreshing them automatically
* Being able to forward some packets to the kernel which will handle them (ARP, ICMP, BGP)
* Rate limiting ICMP packets that are sent to the kernel
* Supporting L3/L4 ACLs
* Gathering statistics and managing ACLs through a cli based on a unixsock
* Being configurable through a configfile

Most of these features are based on various DPDK libs.

## Internals

### Threads

Packet-journey (pktj) is composed of multiple kind of threads:

* pktj, the main thread which is doing all the initialization and are handling signals.
* forward-LCOREID, those threads are doing the forwarding part. They are reading packets from the PMD, doing the processing of those packets and sending them back to the PMD.
* kni-LCOREID, those threads are reading packets from the KNI and sending them to the configured port.
* lcore-slave-LCOREID, those threads are doing nothing, they are just waiting.
* control-SOCKETID, those threads are in charge of receiving NETLINK messages from the IFADDR, ROUTE, NEIGH and LINK groups and handling them.
* cmdline-SOCKETID, those threads are presenting a CLI through the unixsocks.
* rdtsc-SOCKETID, those threads are reading the TSC value and exposing it to the lcore-slave threads.

For optimal performances, the forwarding threads must be alone on their cores. All other threads can be scheduled on the same lcore.

### Processing steps

The forwarding threads are running the main_loop() function. It basically follows these steps:

1. Read up to 32 packet descriptors
2. If none, read again
3. Prepare the ACL processing for the new packets and filter them
4. Find the correct neighbor for the remaining packets by looking into the IPv4 or IPv6 LPM
5. If a packet has no possible next_hop in the LPM or if a packet has the router IP, send it to the KNI and remove it from the rest of the processing loop
6. For each of the remaining packets, set the correct destination MAC address according to the selected next_hop
7. Reorder packets by destination port
8. Send the packets in batch grouped by destination port

## Configuration examples

```
pktj -l 0,1,2,3 -n 4 --socket-mem=4096 --log-level=4 -- \
--configfile /root/devel/router-dpdk/tests/integration/lab00/pktj.conf
```

with `pktj.conf` containing:

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

These settings will launch the following:

* pktj with 2 forwarding threads, on core 1 and 2,
* a KNI tx thread on core 3, and
* the script ```up.sh``` after setting up the KNI.

The script `up.sh` configures the KNI IPv4, IPv6 and MAC addresses. It also
starts some processes (bgpd and zebra in our case).


```
#!/bin/sh

link1=$1
mac1=$2

ip link set $link1 up
ip link add link $link1 name $link1.2000 type vlan id 2000
ip link set $link1.2000 address $mac1
ip link set $link1.2000 up

ip addr add 1.2.3.5/24 dev $link1.2000
ip route add 1.2.4.0/24 via 1.2.3.4
ip addr add 2001:3::5/48 dev $link1.2000
ip route add 2001:4::/48 via 2001:3::4

# delay start because of quagga racy start
sleep 15s

/usr/lib/quagga/zebra &
/usr/lib/quagga/bgpd &
```

You can try this out using our [QEMU test lab](tests/integration).

## Performances

The test scenario is done between 2 physical machines having both a XL710 NIC
and a E5-2630L CPU. The first host is running Packet-Journey; it receives
traffic from the second host and sends it back.

For simulating real life conditions, the tests are done with 500k
routes (something similar to a BGP full view) and 50 ACL (we use scalar
implementation for ACL since the CPU don't have AVX2 instructions). We have
also a percentage of the packets which are forwarded to the KNI instead of
going through the fastpath.

The packets are generated using DPDK-PktGen which is configured for sending 64
Bytes UDP packets with a random source and destination IP. When
Configured with 4 RX queues, Packet-Journey is able to forward 21773.47 mbits.

The graphs of the test scenario are in the [doc](doc/pktj_test_acl_dpdk_4q).
The easiest graphs to read are the ones from pktgen since it shows you the TX
RX rates: [PktGen report](doc/pktj_test_acl_dpdk_4q/results/0/pktgen-perf_report.html).

