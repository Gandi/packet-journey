LINUX:=/home/baloo/work/dev/linux/arch/x86/boot/bzImage
TMP:=/tmp
name:=foo

chroot: multistrap.conf
	rm -rf chroot
	multistrap -f $<

.PHONY: test
test: chroot
	rm -f $(TMP)/vm-$(name)-console.pipe\
		$(TMP)/vm-$(name)-serial.pipe\
		$(TMP)/vm-$(name)-gdb.pipe
	kvm \
		-m 256 -display none \
		-nodefconfig -no-user-config -nodefaults\
		-chardev stdio,id=charserial0,signal=off -device isa-serial,chardev=charserial0,id=serial0 \
		-chardev socket,id=charserial1,path=$(TMP)/vm-$(name)-serial.pipe,server,nowait -device isa-serial,chardev=charserial1,id=serial1 \
		-chardev socket,id=con0,path=$(TMP)/vm-$(name)-console.pipe,server,nowait -mon chardev=con0,mode=readline,default \
		-fsdev local,security_model=passthrough,id=fsdev-root,path=$<,readonly -device virtio-9p-pci,id=fs-root,fsdev=fsdev-root,mount_tag=/dev/root\
		-fsdev local,security_model=passthrough,id=fsdev-lab,path=lab,readonly -device virtio-9p-pci,id=fs-lab,fsdev=fsdev-lab,mount_tag=labshare \
		-gdb unix:$(TMP)/vm-$(name)-gdb.pipe,server,nowait \
		-kernel $(LINUX) -append "uts=$(name) console=ttyS0 root=/dev/root rootflags=trans=virtio,version=9p2000.u ro rootfstype=9p init=/bin/sh -c \"mount -t 9p labshare /media; exec /media/init "\
		-net nic,model=virtio,macaddr=12:22:33:44:55:66 -net tap
#		-kernel $(LINUX) -append "uts=$(name) console=ttyS0 root=/dev/root rootflags=trans=virtio,version=9p2000.u ro rootfstype=9p init='/bin/sh -c \' mount -t 9p labshare /media; exec /bin/sh -i\''"\
