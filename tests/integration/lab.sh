#!/bin/sh

LABNAME="router-dpdk"

ROOT=$(readlink -f ${ROOT:-chroot})
LINUX=$(readlink -f ${LINUX:-bzImage})
DPDK_BUILD="${RTE_SDK}/${RTE_TARGET}"

info() {
    echo "[1;34m[+] $@[0m"
}
error() {
    echo "[1;31m[+] $@[0m"
}
setup_tmp() {
    TMP=/tmp/pktj/
    mkdir $TMP
    chmod 777 $TMP
    #trap "rm -rf $TMP" EXIT
    #info "TMP is $TMP"
}

# Setup a VDE switch
setup_switch_vde() {
    info "Setup VDE switch $1"
    start-stop-daemon -b --make-pidfile --pidfile "$TMP/switch-$1.pid" \
        --start --startas $(which vde_switch) -- \
        --sock "$TMP/switch-$1.sock" < /dev/zero
}

# Setup a bridge
setup_switch() {
    info "Setup switch $1"
    switch="br-dpdk-$1"
    brctl addbr $switch
    ip link set $switch up
    saveifs="$IFS"
    IFS=,
    for vm in $VM; do
        link="tap-$vm-$1"
        ip link set $link up
        brctl addif $switch $link
    done
    IFS="$saveifs"
}

# Start a VM
start_vm() {
    name="r$1"
    info "Start VM $name"
    sshport="1002$1"
    shift

    make chroot

    netargs=""
    saveifs="$IFS"
    IFS=,
    for net in $NET; do
        mac=$(echo $name-$net | sha1sum | \
            awk '{print "52:54:" substr($1,0,2) ":" substr($1, 2, 2) ":" substr($1, 4, 2) ":" substr($1, 6, 2)}')
        netargs="$netargs -netdev tap,id=hn$net,queues=4,vhost=on,script=no,downscript=no,ifname=tap-$name-$net"
        netargs="$netargs -device virtio-net-pci,netdev=hn$net,mq=on,vectors=10,mac=$mac,guest_csum=off,csum=on,gso=on,guest_tso4=on,guest_tso6=on,guest_ecn=on"
    done
    IFS="$saveifs"

    screen -dmS $name \
        $(which qemu-system-x86_64) -enable-kvm -cpu host -smp cores=5,sockets=1 \
        -nodefconfig -no-user-config -nodefaults \
        -m 800 \
        -display none \
        \
        -chardev stdio,id=charserial0,signal=off \
        -chardev socket,id=charserial1,path=$TMP/vm-$name-serial.pipe,server,nowait \
        -device isa-serial,chardev=charserial0,id=serial0 \
        -device isa-serial,chardev=charserial1,id=serial1 \
        \
        -chardev socket,id=con0,path=$TMP/vm-$name-console.pipe,server,nowait \
        -mon chardev=con0,mode=readline,default \
        \
        -fsdev local,security_model=passthrough,id=fsdev-root,path=${ROOT},readonly \
        -device virtio-9p-pci,id=fs-root,fsdev=fsdev-root,mount_tag=/dev/root \
        -fsdev local,security_model=passthrough,id=fsdev-lab,path=$(readlink -f lab),readonly \
        -device virtio-9p-pci,id=fs-lab,fsdev=fsdev-lab,mount_tag=labshare \
        -fsdev local,security_model=passthrough,id=fsdev-build,path=$(readlink -f ../..),readonly \
        -device virtio-9p-pci,id=fs-build,fsdev=fsdev-build,mount_tag=buildshare \
        -fsdev local,security_model=passthrough,id=fsdev-dpdkbuild,path=$RTE_SDK,readonly \
        -device virtio-9p-pci,id=fs-dpdkbuild,fsdev=fsdev-dpdkbuild,mount_tag=dpdkbuildshare \
        \
        -gdb unix:$TMP/vm-$name-kernel-gdb.pipe,server,nowait \
        -kernel $LINUX \
        -append "console=ttyS0 isolcpus=1,2,3 uts=$name root=/dev/root rootflags=trans=virtio,version=9p2000.u ro rootfstype=9p init=/bin/bash -- -c \"mount -t 9p labshare /media; exec /media/init $RTE_SDK ${PWD%%/tests/integration}\"" \
        -net user,hostfwd=tcp::$sshport-:22 -net nic,macaddr=00:16:3e:47:fe:5f,model=e1000 \
        $netargs \
        "$@"
    echo "GDB server listening on.... $TMP/vm-$name-kernel-gdb.pipe"
    echo "monitor listening on....... $TMP/vm-$name-console.pipe"
    echo "ttyS1 listening on......... $TMP/vm-$name-serial.pipe"
}


setup_tmp

#setup_switch_vde   1
#setup_switch_vde   2
#sleep 2

NET=1   start_vm 1
NET=1,2 start_vm 2
NET=2   start_vm 3

sleep 0.5s

VM=r1,r2 setup_switch   1
VM=r2,r3 setup_switch   2
#VM=r1,r2,r3 setup_switch   3

echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $(readlink -f lab)/integration -p 10021 root@localhost"
echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $(readlink -f lab)/integration -p 10022 root@localhost"
echo "ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i $(readlink -f lab)/integration -p 10023 root@localhost"

