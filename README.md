oxmem-fuse
===============

A wrapper for ETRI OmniXtend Memory device.

libfuse-dev package is needed.

\> sudo apt install libfuse-dev

Usage
-----

\> make

\> mkdir om

\> ./oxmem-mount --help

\> ./oxmem-mount -f --netdev=enp23s0 --mac="e4:1d:2d:2e:c4:10" --size=8192 --base=0x0 om/

\> ls -lh om/
total 0
-rw-rw-rw- 1 root root 8589934592 Jul  9 09:03 oxmem

\> ./file-access-test 1

\> umount om/

Misc
------

* FUSE: Filesystem in Userspace
* Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>
* URL: https://github.com/libfuse/libfuse

