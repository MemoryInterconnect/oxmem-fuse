.PHONY: default
default: all ;

all: oxmem-mount oxmem-fuse-dax file-access-test make-increment-file

SRC=oxmem-fuse.c lib-ox-packet.c lib-queue.c

oxmem-mount: $(SRC) Makefile lib-ox-packet.h lib-queue.h
	cc -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=22 $(SRC) -o $@ -lfuse -lpthread
	sudo setcap cap_net_raw+ep $@

oxmem-fuse-dax: oxmem-fuse-dax.c lib-ox-packet.c lib-queue.c Makefile lib-ox-packet.h lib-queue.h
	gcc -D_FILE_OFFSET_BITS=64 -o $@ oxmem-fuse-dax.c lib-ox-packet.c lib-queue.c `pkg-config --cflags --libs fuse3` -lpthread
	sudo setcap cap_net_raw+ep $@

file-access-test: file-access-test.c Makefile
	gcc file-access-test.c -o $@

make-increment-file: make-increment-file.c Makefile
	gcc make-increment-file.c -o $@

.PHONY: clean test

test: oxmem-mount
	mkdir -p /tmp/fuse
	./oxmem-mount /tmp/fuse
	ls -l /tmp/fuse
	cat /tmp/fuse/oxmem
	fusermount -u /tmp/fuse
	
clean:
	rm -f oxmem-mount oxmem-fuse-dax file-access-test make-increment-file
