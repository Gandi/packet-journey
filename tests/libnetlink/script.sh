#!/bin/sh

set -e
set -u

cd `dirname $0`

TEMPDIR=`mktemp -d`
cleanup() {
	rm -rf $TEMPDIR
	kill $process_pid
}
trap cleanup 0

read_timeout() {
	set +e
	# Can't use $$, as it's the parent shell pid, not the subshell.
	# Thus incorrect if invoked in a subshell
	current_pid=$(exec sh -c 'echo $PPID')

	saved_traps="$(trap)"
	if [ "x${saved_traps}" = "x" ]; then saved_traps="trap - ALRM"; fi 
	trap 'eval "${saved_traps}"; set -e; return' ALRM

	(sleep $1; kill -ALRM $current_pid) &
	timer_pid=$!

	read $2

	kill $timer_pid 2>/dev/null
	eval "${saved_traps}"
	set -e
}

skipuntil() {
	read_timeout 5 line1
	stripped=`printf "%.${#1}s" "$line1"`
	if [ "$stripped" = "$1" ]; then
		return 0
	fi
	skipuntil "$1"
}

expectedoutput() {
	read_success=0
	read_timeout 2 line1 || read_success=1
	if [ $read_success -ne 0 ]; then
		echo $2 ", expected" $1 ": got nothing (timeout)" >&2
		exit 1;
	fi
	if [ "$line1" != "$1" ]; then
		echo $2 ", expected" $1 ": " $line1 >&2
		exit 1;
	fi
}

ip link add eth0 type dummy
ip link set dev eth0 up

mkfifo $TEMPDIR/fifo
$1 >$TEMPDIR/fifo &
process_pid=$!

(
skipuntil "START"

ip addr add 1.2.3.1/24 dev eth0
expectedoutput "addr4 add 1.2.3.1/24 dev eth0" "We should have read new address through netlink"
ip addr add 1::1/48 dev eth0
expectedoutput "addr6 add 1::1/48 dev eth0" "We should have read new address through netlink"

ip route add 1.2.4.0/24 via 1.2.3.254
expectedoutput "route4 add 1.2.4.0/24 via 1.2.3.254" "We should have read new route through netlink"
ip route del 1.2.4.0/24 via 1.2.3.254
expectedoutput "route4 del 1.2.4.0/24 via 1.2.3.254" "We should have read route deletion through netlink"

ip route add 1::/48 via fe80::1 dev eth0
expectedoutput "route6 add 1::/48 via fe80::1" "We should have read new route through netlink"
ip route del 1::/48 via fe80::1 dev eth0
expectedoutput "route6 del 1::/48 via fe80::1" "We should have read route deletion through netlink"

ip addr del 1::1/48 dev eth0
expectedoutput "addr6 del 1::1/48 dev eth0" "We should have read new address through netlink"
ip addr del 1.2.3.1/24 dev eth0
expectedoutput "addr4 del 1.2.3.1/24 dev eth0" "We should have read a delete address through netlink"

ip neigh add 1.2.3.2 lladdr 11:22:33:44:55:66 dev eth0
expectedoutput "neigh4 add 1.2.3.2 lladdr 11:22:33:44:55:66 nud PERMANENT dev eth0" "We should have read new neigghbour through netlink"
ip neigh add 1::2 lladdr 11:22:33:44:55:67 dev eth0
expectedoutput "neigh6 add 1::2 lladdr 11:22:33:44:55:67 nud PERMANENT dev eth0" "We should have read new neigghbour through netlink"
kill $process_pid;

expectedoutput "EOF" "We should have end the test with no further content"
) < $TEMPDIR/fifo


wait $process_pid || (
	echo "process returned non-zero return code, check logs" >&2;
	exit 1)
exitcode=$?

exit 0
