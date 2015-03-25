#!/bin/sh

set -e
set -u

cd `dirname $0`

TEMPDIR=`mktemp -d`
cleanup() {
	rm -rf $TEMPDIR
}
trap cleanup 0

skipuntil() {
	read line1
	stripped=`printf "%.${#1}s" "$line1"`
	if [ "$stripped" = "$1" ]; then
		return 0
	fi
	skipuntil "$1"
}

expectedoutput() {
	read line1
	if [ "$line1" != "$1" ]; then
		echo $2 ", expected" $1 ": " $line1 >&2
		exit 1;
	fi
}


mkfifo $TEMPDIR/fifo
$1 >$TEMPDIR/fifo &
process_pid=$!

(
skipuntil "EAL: Support maximum"
skipuntil "EAL: Detected"

expectedoutput "EOF" "We should have end the test with no further content"
) < $TEMPDIR/fifo

kill $process_pid;

wait $process_pid || (
	echo "process returned non-zero return code, check logs" >&2;
	exit 1)
exitcode=$?

exit 0
