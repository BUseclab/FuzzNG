#!/bin/bash
#
ulimit -n 1048576
mknod /dev/fuzzer c $(cat /proc/devices  | grep fuzz | cut -f 1 -d " ") 0
mknod /dev/megaraid_sas_ioctl c $(cat /proc/devices  | grep megaraid_sas_ioctl | cut -f 1 -d " ") 0
mknod /dev/megadev_legacy c $(cat /proc/devices  | grep megadev_legacy | cut -f 1 -d " ") 0 &> /dev/ttyS0
mknod /dev/infiniband_verbs c $(cat /proc/devices  | grep infiniband_verbs | tail -n1 | cut -f 1 -d " ") 0 &> /dev/ttyS0
echo 0 | tee /proc/sys/kernel/randomize_va_space &> /dev/ttyS0
sleep 10
/etc/init.d/crond stop 
mkdir /dev/binderfs &> /dev/ttyS0
mount -t binder binder /dev/binderfs &> /dev/ttyS0
find /dev/ > /dev/ttyS0
cp -r /hostshare/ /tmp/agent
cd /tmp/agent
make clean; make &> /dev/ttyS0
LD_BIND_NOW=1 nice -20 ./fuzz &> /dev/ttyS0
echo Returned $?
shutdown now
