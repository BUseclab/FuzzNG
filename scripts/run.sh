#!/bin/bash
#set -x

if [ -z "$PORT" ]; then
    PORT=10021
fi

if [ -z "$SHARE_DIR" ]; then
    SHARE_DIR=$PROJECT_ROOT/agent/
fi


if [ -z "$CORPUS_DIR" ]; then
    CORPUS_DIR=CORPUS/
    mkdir -p $CORPUS_DIR
fi

if [ -z "$kernel" ]; then
    kernel=$PROJECT_ROOT/kernel-build/arch/x86/boot/bzImage
fi

if [ -z "$qemu" ]; then
    qemu=$PROJECT_ROOT/qemu-build/qemu-fuzz-x86_64
fi

image=$PROJECT_ROOT/images/bullseye.img

export QEMU_SNAP_ARGS="-cpu host,kvm=on,svm=on \
    -machine q35,vmport=off,smbus=off,acpi=off,usb=off,graphics=off -m 1G \
    -kernel $kernel \
    -append 'root=/dev/vda earlyprintk=ttyS0 console=ttyS0 nokaslr silent notsc acpi=off \
    kvm-intel.nested=1 kvm-intel.unrestricted_guest=1 kvm-intel.vmm_exclusive=1 kvm-intel.fasteoi=1 \
    kvm-intel.ept=1 kvm-intel.flexpriority=1 kvm-intel.vpid=1 kvm-intel.emulate_invalid_guest_state=1 \
    kvm-intel.eptad=1 kvm-intel.enable_shadow_vmcs=1 kvm-intel.pml=1 kvm-intel.enable_apicv=1' \
    -drive file=$image,id=dr0,format=raw,if=none \
    -virtfs local,path=$SHARE_DIR,mount_tag=host0,security_model=none,id=host0,readonly=on \
    -device virtio-blk-pci,drive=dr0 \
    -nographic -accel kvm -nodefaults -nographic  \
    -drive file=null-co://,if=none,id=nvm  -vga virtio \
    -device megasas,id=scsi0 \
    -device scsi-hd,drive=drive0,bus=scsi0.0,channel=0,scsi-id=0,lun=0 \
    -drive file=null-co://,if=none,id=drive0 \
    -device nvme,serial=deadbeef,drive=nvm \
    -serial none -snapshot -cdrom /dev/null $EXTRA_ARGS"

if [[ -n "$NET_ENABLE" ]]; then
    export QEMU_SNAP_ARGS="$QEMU_SNAP_ARGS \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0,host=10.0.2.11,hostfwd=tcp:127.0.0.1:$PORT-:22"
fi

echo $QEMU_SNAP_ARGS
	$qemu \
        -rss_limit_mb=8096 \
        -use_value_profile=1  \
        -detect_leaks=0 \
        -dict=$PROJECT_ROOT/scripts/dict  \
        -len_control=200 \
        -reload=60 \
        $EXTRA_FUZZARGS \
        $CORPUS_DIR
