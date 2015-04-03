#!/bin/sh

LABNAME="router-dpdk"

ROOT=$(readlink -f ${ROOT:-chroot})
LINUX=$(readlink -f ${LINUX:-bzImage})
DPDK_BUILD="${RTE_SDK}/${RTE_BUILD}"

WHICH=$(which which)

info() {
    echo "[1;34m[+] $@[0m"
}
error() {
    echo "[1;31m[+] $@[0m"
}
setup_tmp() {
    TMP=$(mktemp -d)
    #trap "rm -rf $TMP" EXIT
    #info "TMP is $TMP"
}

# Setup a VDE switch
setup_switch() {
    info "Setup switch $1"
    start-stop-daemon -b --make-pidfile --pidfile "$TMP/switch-$1.pid" \
        --start --startas $($WHICH vde_switch) -- \
        --sock "$TMP/switch-$1.sock" < /dev/zero
}



# Start a VM
start_vm() {
    info "Start VM $1"
    name="$1"
    shift

    make chroot

    netargs=""
    saveifs="$IFS"
    IFS=,
    for net in $NET; do
        mac=$(echo $name-$net | sha1sum | \
            awk '{print "52:54:" substr($1,0,2) ":" substr($1, 2, 2) ":" substr($1, 4, 2) ":" substr($1, 6, 2)}')
        netargs="$netargs -net nic,model=virtio,macaddr=$mac,vlan=$net"
        netargs="$netargs -net vde,sock=$TMP/switch-$net.sock,vlan=$net"
    done
    IFS="$saveifs"

    screen -dmS $name \
        $($WHICH qemu-system-x86_64) -enable-kvm -cpu host -smp 2 \
        -nodefconfig -no-user-config -nodefaults \
        -m 256 \
        -display none \
        \
        -chardev stdio,id=charserial0,signal=off \
        -device isa-serial,chardev=charserial0,id=serial0 \
        -chardev socket,id=charserial1,path=$TMP/vm-$name-serial.pipe,server,nowait \
        -device isa-serial,chardev=charserial1,id=serial1 \
        \
        -chardev socket,id=con0,path=$TMP/vm-$name-console.pipe,server,nowait \
        -mon chardev=con0,mode=readline,default \
        \
        -fsdev local,security_model=passthrough,id=fsdev-root,path=${ROOT},readonly \
        -device virtio-9p-pci,id=fs-root,fsdev=fsdev-root,mount_tag=/dev/root \
        -fsdev local,security_model=passthrough,id=fsdev-lab,path=$(readlink -f lab),readonly \
        -device virtio-9p-pci,id=fs-lab,fsdev=fsdev-lab,mount_tag=labshare \
        -fsdev local,security_model=passthrough,id=fsdev-build,path=$(readlink -f ../../build),readonly \
        -device virtio-9p-pci,id=fs-build,fsdev=fsdev-build,mount_tag=buildshare \
        -fsdev local,security_model=passthrough,id=fsdev-dpdkbuild,path=$DPDK_BUILD,readonly \
        -device virtio-9p-pci,id=fs-dpdkbuild,fsdev=fsdev-dpdkbuild,mount_tag=dpdkbuildshare \
        \
        -gdb unix:$TMP/vm-$name-gdb.pipe,server,nowait \
        -kernel $LINUX \
        -append "console=ttyS0 uts=$name root=/dev/root rootflags=trans=virtio,version=9p2000.u ro rootfstype=9p init=/bin/sh -c \"mount -t 9p labshare /media; exec /media/init" \
        $netargs \
        "$@"
    echo "GDB server listening on.... $TMP/vm-$name-gdb.pipe"
    echo "monitor listening on....... $TMP/vm-$name-console.pipe"
    echo "ttyS1 listening on......... $TMP/vm-$name-serial.pipe"
}


setup_tmp

setup_switch   1
setup_switch   2

sleep 2

NET=1   start_vm r1
NET=1,2 start_vm r2
NET=2   start_vm r3


