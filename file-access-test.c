#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mman.h>
#include <string.h>

#define FILE_PATH "/home/swsok/oxmem-fuse/om/oxmem"

// #define SIZE (4*1024)

int main(int argc, char **argv)
{
    int fd;
    int *write_buffer;
    int *read_buffer;
    int nread, nwrite, i;
    int size;
    int *mmap_addr;

    if (argc < 2) {
	printf("Usage: %s [n] (n = write, read and compare n kb data)\n",
	       argv[0]);
	return 0;
    }

    size = atoi(argv[1]) * 1024;

    fd = open(FILE_PATH, O_RDWR);

    if (fd < 0) {
	printf("file open error - %s, errno=%d\n", FILE_PATH, errno);
	return 0;
    }

    mmap_addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
//    mmap_addr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (mmap_addr == MAP_FAILED) {
	printf("mmap error = %d (%s)\n", errno, strerror(errno));
	goto close_file;
    }

    
     write_buffer = malloc(size); 
     read_buffer = malloc(size);

if (1) {     
     srand(time(NULL)); 
     for (i=0; i<size/sizeof(int); i++) {
     	write_buffer[i] = rand(); 
     }
     
     nwrite = write(fd, write_buffer, size);
}

if (1) {     
     lseek(fd, 0, SEEK_SET);
      
     nread = read(fd, read_buffer, size);
     
     for (i=0; i<size/sizeof(int); i++) { 
	     if ( write_buffer[i] != read_buffer[i] ) { 
		     printf("%ld write=%x read=%x\n", i*sizeof(int), write_buffer[i], read_buffer[i]); 
		     break; 
	     } 
     }
     
     if ( i >= size/sizeof(int) ) { 
	     printf("write_buffer == read_buffer\n"); 
     } else { 
	     printf("write_buffer != read_buffer\n");
     }
}
     free(write_buffer); 
     free(read_buffer); 
     
    if (mmap_addr != MAP_FAILED)
	munmap(mmap_addr, 4096);

close_file:
    close(fd);

    return 0;
}

