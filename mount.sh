#!/bin/bash

#sudo mount -t ramfs ramfs /mnt/ramfs/
#sudo chmod -R a+wr /mnt/ramfs/
#dd if=/dev/zero of=/mnt/ramfs/oxmem_backend bs=1G count=4
sudo umount om/
./oxmem-mount -f --netdev=enp179s0f0np0 --mac="04:3f:72:dd:0b:05" --size=1024 --base=0x0 om/
#./oxmem-mount -f --netdev=enp179s0 --mac="e4:1d:2d:2e:bd:f0" --size=2 --base=0x0 om/
#sudo ./oxmem-mount -f --netdev=enp23s0 --mac="00:12:32:ff:ff:fa" --size=8192 --base=0x100000000 om/ 
#./oxmem-mount -f --netdev=enp23s0 --mac="00:12:32:ff:ff:fa" --size=8192 --base=0x100000000 om/ 

