.PHONY: default
default: all ;

all: oxmem-mount file-access-test make-increment-file

SRC=oxmem-fuse.c lib-ox-packet.c lib-queue.c

oxmem-mount: $(SRC) Makefile lib-ox-packet.h lib-queue.h
	cc -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=22 $(SRC) -o oxmem-mount -lfuse -lpthread
	sudo setcap cap_net_raw+ep oxmem-mount

file-access-test: file-access-test.c Makefile
	gcc file-access-test.c -o file-access-test

make-increment-file: make-increment-file.c Makefile
	gcc make-increment-file.c -o make-increment-file

.PHONY: clean test

test: oxmem-mount
	mkdir -p /tmp/fuse
	./oxmem-mount /tmp/fuse
	ls -l /tmp/fuse
	cat /tmp/fuse/oxmem
	fusermount -u /tmp/fuse
	
clean:
	rm oxmem-mount file-access-test make-increment-file
