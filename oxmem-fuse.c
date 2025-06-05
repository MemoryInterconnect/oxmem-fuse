/*
 * FUSE: Filesystem in Userspace Copyright (C) 2001-2005 Miklos Szeredi
 * <miklos@szeredi.hu>
 * 
 * This program can be distributed under the terms of the GNU GPL. See the 
 * file COPYING. 
 */

#include <stddef.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pthread.h>
#include <semaphore.h>
#include <limits.h>
#include <sys/stat.h>
#include "lib-ox-packet.h"
#include "lib-queue.h"

static const char *oxmem_path = "/oxmem";

static struct stat root_st;

static struct oxmem_info_struct oxmem_info;

static struct ox_request ox_request_list[OX_REQUEST_LIST_LENGTH];

#define OPTION(t, p)                           \
	    { t, offsetof(struct options, p), 1 }

static struct options {
    const char *mac;
    const char *size;
    const char *base;
    const char *netdev;
    int show_help;
} options;

static const struct fuse_opt option_spec[] = {
    OPTION("--mac=%s", mac),
    OPTION("-M=%s", mac),
    OPTION("--size=%s", size),
    OPTION("-S=%s", size),
    OPTION("--base=%s", base),
    OPTION("-B=%s", base),
    OPTION("--netdev=%s", netdev),
    OPTION("-N=%s", netdev),
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    FUSE_OPT_END
};

void *oxmem_send_thread(void *arg);
void *oxmem_recv_thread(void *arg);

int try_to_post_ox_request(int connection_id, struct ox_packet_struct *ox_p, int expect_tl_msg);
int post_ox_request(int connection_id, struct ox_packet_struct *ox_p, int expect_tl_msg, char * target_buf/* for read op only */);
int free_ox_request(int request_idx);

static int oxmem_getattr(const char *path, struct stat *stbuf)
{
    int res = 0;
    struct stat *st = &oxmem_info.st;

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_mode = S_IFDIR | 0755;
	stbuf->st_nlink = 2;
	memcpy(&(stbuf->st_atim), &root_st.st_atim,
	       sizeof(struct timespec));;
	memcpy(&(stbuf->st_mtim), &root_st.st_mtim,
	       sizeof(struct timespec));;
	memcpy(&(stbuf->st_ctim), &root_st.st_ctim,
	       sizeof(struct timespec));;
	stbuf->st_size = 4096;
    } else if (strcmp(path, oxmem_path) == 0) {
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_mode = S_IFREG | 0666;
	stbuf->st_nlink = 1;
	memcpy(&(stbuf->st_atim), &st->st_atim, sizeof(struct timespec));;
	memcpy(&(stbuf->st_mtim), &st->st_mtim, sizeof(struct timespec));;
	memcpy(&(stbuf->st_ctim), &st->st_ctim, sizeof(struct timespec));;
	stbuf->st_size = st->st_size;
	stbuf->st_uid = st->st_uid;
	stbuf->st_gid = st->st_gid;
    } else
	res = -ENOENT;

    return res;
}

static int
oxmem_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
	      off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    if (strcmp(path, "/") != 0)
	return -ENOENT;

    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, oxmem_path + 1, NULL, 0);

    return 0;
}

static int oxmem_open(const char *path, struct fuse_file_info *fi)
{
    int ret = 0;
    int idx;
    struct ox_packet_struct send_ox_p;


    PRINT_LINE("OPEN %s\n", path);
    if (strcmp(path, oxmem_path) != 0)
	return -ENOENT;

    // if direct_io == 0, mmap MAP_SHARED is possible
//    fi->direct_io = FUSE_DIRECT_IO;
    fi->direct_io = FUSE_DIRECT_IO;

    // if connection is not made, send Open_Connection packet
    if (oxmem_info.connection_id >= 0) {
	return 0;
    }

    //for channel A
    oxmem_info.connection_id =
	make_open_connection_packet(oxmem_info.sockfd, oxmem_info.netdev,
				    oxmem_info.mac_addr, &send_ox_p);

    idx = post_ox_request(oxmem_info.connection_id, &send_ox_p, 0, NULL);

    PRINT_LINE("OPEN oxmem_info.connection_id=%d idx = %d\n",
	      oxmem_info.connection_id, idx);

    // wait response and process it.
    sem_wait(&ox_request_list[idx].sem_wait);
    free_ox_request(idx);

    //for channel D
    send_ox_p.tloe_hdr.msg_type = NORMAL;
    send_ox_p.tloe_hdr.chan = CHANNEL_D;

    idx = post_ox_request(oxmem_info.connection_id, &send_ox_p, 0, NULL);

    PRINT_LINE("OPEN oxmem_info.connection_id=%d idx = %d\n",
	      oxmem_info.connection_id, idx);

    sem_wait(&ox_request_list[idx].sem_wait);
    free_ox_request(idx);

    PRINT_LINE("6\n");
    return ret;
}

static int oxmem_release(const char *path, struct fuse_file_info *fi)
{
    struct ox_packet_struct send_ox_p;
    int idx;

    PRINT_LINE("RELEASE %s\n", path);
    if (strcmp(path, oxmem_path) != 0)
	return -ENOENT;

    // send Close_Connection packet
    if (oxmem_info.connection_id < 0) {
	return -ENXIO;
    }

    make_close_connection_packet(oxmem_info.connection_id, &send_ox_p);
    idx = post_ox_request(oxmem_info.connection_id, &send_ox_p, 0, NULL);

    PRINT_LINE("RELEASE idx = %d\n", idx);

    // wait response and process it.
    sem_wait(&ox_request_list[idx].sem_wait);
    free_ox_request(idx);

    delete_connection(oxmem_info.connection_id);
    oxmem_info.connection_id = -1;

    PRINT_LINE("7\n");
    return 0;
}

static int copy_recv_data_to_buf(char * target_buf, struct ox_request * ox_req){
	uint64_t be64_temp;
	struct tl_msg_header_chan_AD tl_msg_ack;
	int start_flit_num = 0, i;
	uint64_t tl_msg_mask = ox_req->recv_ox.tl_msg_mask;
	
	if ( tl_msg_mask == 0 ) {
		printf("tl_msg_mask is 0. this function(%s) should be not called.\n", __FUNCTION__);
		return -1;
	}

	// find start point of valid flit
	for (i=0; i<64; i++) {
		if ( (tl_msg_mask >> i) & 0x1 == 1) break;
	}

	be64_temp = be64toh(ox_req->recv_ox.flits[i]);
	memcpy(&(tl_msg_ack), &be64_temp, sizeof(uint64_t));
	memcpy(target_buf, &ox_req->recv_ox.flits[i+1], 1 << tl_msg_ack.size);
	return 1 << tl_msg_ack.size;
}

static int
oxmem_read(const char *path, char *buf, size_t size, off_t offset,
	   struct fuse_file_info *fi)
{
    size_t len;
    int fd;
    (void) fi;
    struct ox_packet_struct send_ox_p;
    uint64_t send_flits[256];	// 256*8 = 2kb
    long int remain_size = size, read_size;
    struct tl_msg_header_chan_AD tl_msg_ack;
    uint64_t be64_temp;
    int i;
    int idx[4096] = { -1, };
    int temp_idx;
    int j = 0;
    char * temp_target_buf;

    PRINT_LINE1("READ %s - offset %lx size %ld\n", path, offset, size);

    if (strcmp(path, oxmem_path) != 0) {
	printf("READ %s %d \n", path, __LINE__);
	return -ENOENT;
    }

    if (offset + size > oxmem_info.st.st_size) {
	printf("READ %s %d offset=%lu oxmem_info.st.st_size=%lu\n", path,
	       __LINE__, offset, oxmem_info.st.st_size);
	return -ENXIO;
    }

    if (oxmem_info.connection_id < 0) {
	printf("READ %s %d \n", path, __LINE__);
	return -ENXIO;
    }

    while (remain_size > 0) {
	read_size = (remain_size > READ_WRITE_UNIT) ? READ_WRITE_UNIT : remain_size;
	for (i = 10; i >= 0; i--) {
	    if (read_size >= (1 << i)) {
		read_size = 1 << i;
		break;
	    }
	}

	PRINT_LINE("READ %s offset=%lx remain_size=%ld read_size=%ld\n",
		  path, offset + (size - remain_size), remain_size,
		  read_size);

	bzero(send_flits, 2048);
	make_get_op_packet(oxmem_info.connection_id, read_size,
			   offset + (size - remain_size), &send_ox_p,
			   send_flits);

	temp_target_buf = buf + (size - remain_size);
	PRINT_LINE("buf=%p temp_target_buf=%p size=%lu remain_size=%lu\n", buf, temp_target_buf, size, remain_size);
#if 0
	temp_idx =
		post_ox_request(oxmem_info.connection_id, &send_ox_p, 1, temp_target_buf);
	PRINT_LINE("temp_idx = %d\n", temp_idx);
PRINT_LINE("seq_num %x sent\n", ox_request_list[temp_idx].seq_num);
	sem_wait(&ox_request_list[temp_idx].sem_wait);
	copy_recv_data_to_buf(ox_request_list[temp_idx].target_buf, &ox_request_list[temp_idx]);
	free_ox_request(temp_idx);
	remain_size -= (read_size);
    }


#else
	do {
	    // try to post the request
	    temp_idx =
		post_ox_request(oxmem_info.connection_id, &send_ox_p, 1, temp_target_buf);

	    // if the queue is full, clean up completed requests.
	    if (temp_idx < 0) {
		for (i = 0; i < j; i++) {
		    if (idx[i] < 0)
			continue;
		    if (0 == sem_trywait(&ox_request_list[idx[i]].sem_wait)) {
			copy_recv_data_to_buf(ox_request_list[idx[i]].target_buf, &ox_request_list[idx[i]]);

			free_ox_request(idx[i]);
			idx[i] = -1;
		    }
		}
	    }
	} while (temp_idx < 0);

	idx[j++] = temp_idx;
	remain_size -= (read_size);
    }

    // wait responses and process them.
    for (i = 0; i < j; i++) {
	if (idx[i] < 0)
	    continue;
	sem_wait(&ox_request_list[idx[i]].sem_wait);

	PRINT_LINE("READ i=%d idx=%d\n", i, idx[i]);

	// check if data is received. currently only tl_msg_count=1 is supported. 
	copy_recv_data_to_buf(ox_request_list[idx[i]].target_buf, &ox_request_list[idx[i]]);

	free_ox_request(idx[i]);
	idx[i] = -1;
    }

#endif
    PRINT_LINE("READ 0x%lx return %ld\n", offset, size);

    return size;
}

static int
oxmem_write(const char *path, const char *buf, size_t size, off_t offset,
	    struct fuse_file_info *fi)
{
    size_t len;
    int fd;
    (void) fi;
    struct stat st;
    struct ox_packet_struct send_ox_p, ack_ox_p;
    uint64_t send_flits[256];	// 256*8 = 2kb
    long int remain_size = size, write_size;
    struct tl_msg_header_chan_AD tl_msg_ack;
    uint64_t be64_temp;
    int i, j = 0;
    int idx[4096] = { -1, };
    int temp_idx;

    PRINT_LINE1("WRITE %s - offset %lx size %ld\n", path, offset, size);

    if (strcmp(path, oxmem_path) != 0)
	return -ENOENT;

    if (offset + size > oxmem_info.st.st_size)
	return -ENXIO;

    while (remain_size > 0) {
	write_size =
	    (remain_size >
	     READ_WRITE_UNIT) ? READ_WRITE_UNIT : remain_size;

	for (i = 10; i >= 0; i--) {
	    if (write_size >= (1 << i)) {
		write_size = 1 << i;
		break;
	    }
	}

	make_putfull_op_packet(oxmem_info.connection_id,
			       buf + (size - remain_size), write_size,
			       offset + (size - remain_size), &send_ox_p,
			       send_flits);
#if 0
	    temp_idx =
		post_ox_request(oxmem_info.connection_id, &send_ox_p, 1, NULL);

	    sem_wait(&ox_request_list[temp_idx].sem_wait);
	    free_ox_request(temp_idx);
	remain_size -= write_size;
    }

#else
	do {
	    // try to post the request
	    temp_idx =
		post_ox_request(oxmem_info.connection_id, &send_ox_p, 1, NULL);

	    // if the queue is full, clean up completed requests.
	    if (temp_idx < 0) {
		for (i = 0; i < j; i++) {
		    if (idx[i] < 0)
			continue;
		    if (0 ==
			sem_trywait(&ox_request_list[idx[i]].sem_wait)) {

			free_ox_request(idx[i]);
			idx[i] = -1;
		    }
		}
	    }
	} while (temp_idx < 0);

	idx[j++] = temp_idx;

	remain_size -= write_size;
    }
    // wait responses and free request queue entries.
    for (i = 0; i < j; i++) {
	if (idx[i] < 0)
	    continue;
	PRINT_LINE("checking if idx=%d (seq_num=%x) is responed\n", idx[i], ox_request_list[idx[i]].seq_num);
	sem_wait(&ox_request_list[idx[i]].sem_wait);
	PRINT_LINE("idx=%d is responed\n", idx[i]);

	free_ox_request(idx[i]);
	idx[i] = -1;
    }
#endif
    return size;
}



static struct fuse_operations oxmem_oper = {
    .getattr = oxmem_getattr,
    .readdir = oxmem_readdir,
    .open = oxmem_open,
    .read = oxmem_read,
    .write = oxmem_write,
    .release = oxmem_release,
};

static void show_help(const char *progname)
{
    printf("usage: %s [options] <mountpoint>\n\n", progname);
    printf("File-system specific options:\n"
	   "    --netdev=DEV        Eternet interface to use\n"
	   "                        (default: \"enp179s0\")\n"
	   "    --mac=MAC           MAC address of OX mem endpoint\n"
	   "                        (default: \"e4:1d:2d:2e:bd:f0\")\n"
	   "    --size=N            size in MB of OX mem endpoint\n"
	   "                        (default \"8192\")\n" "\n");
}

static pthread_mutex_t ox_request_list_lock;
sem_t send_thread_wait;
sem_t post_queue_wait;

void destroy_ox_request_list(void)
{
    pthread_mutex_destroy(&ox_request_list_lock);
}

static int init_ox_request_list(void)
{
    int i;

    bzero(ox_request_list,
	  sizeof(struct ox_request) * OX_REQUEST_LIST_LENGTH);

    for (i = 0; i < OX_REQUEST_LIST_LENGTH; i++) {
	ox_request_list[i].connection_id = -1;
	ox_request_list[i].seq_num = -1;
	ox_request_list[i].target_buf = NULL;
	sem_init(&ox_request_list[i].sem_wait, 0, 1);	// binary
	// semaphore
    }

    if (pthread_mutex_init(&ox_request_list_lock, NULL) != 0) {
	printf("\n mutex init has failed\n");
	return 1;
    }

    sem_init(&send_thread_wait, 0, 1);
    sem_init(&post_queue_wait, 0, 1);

}

static Queue q_free, q_posted, q_sent, q_responded;

// init ox_request queues - q_free, q_posted, q_sent, and q_responded
static int init_ox_request_queues(void)
{
	int i;

	initQueue(&q_free);
	initQueue(&q_posted);
	initQueue(&q_sent);
	initQueue(&q_responded);

	//Put all ox_request entries into q_free
	for(i=0; i<OX_REQUEST_LIST_LENGTH; i++) {
		enqueue(&q_free, i);
	}

	return 0;
}

int main(int argc, char *argv[])
{
    int ret;
    int i;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    uint32_t mac_values[6];
    struct sockaddr_ll saddr;
    pthread_t recv_thread, send_thread;
    int recv_thread_id,
	recv_thread_status, send_thread_id, send_thread_status;
    char *end;

    options.netdev = strdup("enp179s0");
    options.mac = strdup("e4:1d:2d:2e:bd:f0");
    options.size = strdup("8192");
    options.base = strdup("0x0");
    /*
     * Parse options 
     */
    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
	return 1;

    if (options.show_help) {
	show_help(argv[0]);
	assert(fuse_opt_add_arg(&args, "--help") == 0);
	args.argv[0][0] = '\0';
    }

    // configure root directory stat
    root_st.st_mode = S_IFDIR | 0755;
    root_st.st_nlink = 2;
    clock_gettime(CLOCK_REALTIME, &root_st.st_atim);
    clock_gettime(CLOCK_REALTIME, &root_st.st_mtim);
    clock_gettime(CLOCK_REALTIME, &root_st.st_ctim);

    // configure oxmem_info
    strcpy(oxmem_info.netdev, options.netdev);
    oxmem_info.netdev_id = if_nametoindex(options.netdev);
    if (oxmem_info.netdev_id == 0) {
	PRINT_LINE("netdev = %s is not valid.\n", options.netdev);
	return -1;
    }

    if (6 ==
	sscanf(options.mac, "%2x:%2x:%2x:%2x:%2x:%2x", &mac_values[0],
	       &mac_values[1], &mac_values[2], &mac_values[3],
	       &mac_values[4], &mac_values[5])) {
	for (i = 0; i < 6; i++)
	    oxmem_info.mac_addr += (uint64_t) mac_values[i] << (i * 8);
	PRINT_LINE("MAC_in_bigendian = %lx\n", oxmem_info.mac_addr);
    } else {
	PRINT_LINE("MAC value is not valid - %s\n", options.mac);
	return -1;		// format is not MAC address
    }

    oxmem_info.base = strtoull(options.base, &end, 16);
    if (end == options.base) {
	PRINT_LINE("--base=%s is invalid hex digit.\n", options.base);
	return -1;
    } else if (oxmem_info.base == ULLONG_MAX) {
	PRINT_LINE("--base=%s is too big.\n", options.base);
	return -1;
    }

    // oxmem stat
    oxmem_info.st.st_mode = 0555;
    clock_gettime(CLOCK_REALTIME, &oxmem_info.st.st_atim);
    clock_gettime(CLOCK_REALTIME, &oxmem_info.st.st_mtim);
    clock_gettime(CLOCK_REALTIME, &oxmem_info.st.st_ctim);
    oxmem_info.st.st_size = oxmem_info.size =
	atol(options.size) * 1024 * 1024;
    oxmem_info.connection_id = -1;

    PRINT_LINE("size = %lu bytes\n", oxmem_info.size);

    // Create RAW socket
    oxmem_info.sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (oxmem_info.sockfd == -1) {
	PRINT_LINE("Socket creation error.\n");
	oxmem_info.sockfd = 0;
	return -ENOENT;
    }

    bzero(&saddr, sizeof(struct sockaddr_ll));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = oxmem_info.netdev_id;

    // bind with interface
    if (bind(oxmem_info.sockfd, (struct sockaddr *) &saddr, sizeof(saddr))
	< 0) {
	PRINT_LINE("Socket bind error\n");
	close(oxmem_info.sockfd);
	return -errno;
    }

    // init ox_request_list
    if (0 != init_ox_request_list()) {
	PRINT_LINE("init_ox_request_list() error\n");
	ret = -errno;
    }

    // init ox_request queues - q_free, q_posted, q_sent, and q_responded
    if (0 != init_ox_request_queues()) {
	PRINT_LINE("init_ox_request_queues() error\n");
	ret = -errno;
    }

    // Create send/recv thread
    recv_thread_id =
	pthread_create(&recv_thread, NULL, oxmem_recv_thread,
		       (void *) &oxmem_info);
    if (recv_thread_id < 0) {
	PRINT_LINE("Thread creation fail\n");
	return -1;
    }

    send_thread_id =
	pthread_create(&send_thread, NULL, oxmem_send_thread,
		       (void *) &oxmem_info);
    if (recv_thread_id < 0) {
	PRINT_LINE("Thread creation fail\n");
	return -1;
    }

    ret = fuse_main(args.argc, args.argv, &oxmem_oper);

    fuse_opt_free_args(&args);

    // close socket
    destroy_ox_request_list();
    close(oxmem_info.sockfd);
    PRINT_LINE("umounted\n");

    return ret;
}

int post_ox_request(int connection_id, struct ox_packet_struct *ox_p, int expect_tl_msg, char * target_buf)
{
    int i, index;

    pthread_mutex_lock(&ox_request_list_lock);

    index = dequeue(&q_free);

    if( index >= 0 ) {
    ox_request_list[index].connection_id = connection_id;
    ox_request_list[index].expect_tl_msg = expect_tl_msg;
    memcpy(&ox_request_list[index].send_ox, ox_p, sizeof(struct ox_packet_struct));
    set_seq_num_to_ox_packet(ox_request_list[index].connection_id, &ox_request_list[index].send_ox);
    ox_request_list[index].seq_num = ox_request_list[index].send_ox.tloe_hdr.seq_num;
    ox_request_list[index].target_buf = target_buf;

PRINT_LINE("seq_num = %x\n", ox_request_list[index].send_ox.tloe_hdr.seq_num);
    ox_struct_to_packet(&ox_request_list[index].send_ox, ox_request_list[index].send_buffer, &ox_request_list[index].send_size);

    sem_init(&ox_request_list[index].sem_wait, 0, 0);
    enqueue(&q_posted, index);
    sem_post(&send_thread_wait);
    
    }

    pthread_mutex_unlock(&ox_request_list_lock);

	return index;
}

// get a queued request
int get_next_ox_request(void)
{
    int i, index=0;

    pthread_mutex_lock(&ox_request_list_lock);

    index = dequeue(&q_posted);

PRINT_LINE("dequeued from q_posted index = %d\n", index);
    if( index >= 0 ) {    
PRINT_LINE("enqueued to q_sent index = %d\n", index);
	    enqueue(&q_sent, index);
    }

    pthread_mutex_unlock(&ox_request_list_lock);

    return index;
}

// find matched ox_request(originated one), save the response and wake up
// the listner.
int
add_response_ox_request(int connection_id, int seq_num, char *recv_buffer,
			int recv_size, int tl_msg_included)
{
    int i, temp_index;
    Node * temp = NULL;

    pthread_mutex_lock(&ox_request_list_lock);

    temp = q_sent.front;
    while (temp) {
	    temp_index = temp->data;
	if ( temp_index >= 0
		&& ox_request_list[temp_index].seq_num == seq_num
		&& ox_request_list[temp_index].connection_id == connection_id
		&& ox_request_list[temp_index].expect_tl_msg == tl_msg_included ) {
		
		memcpy(ox_request_list[temp_index].recv_buffer, recv_buffer, recv_size);
		packet_to_ox_struct(ox_request_list[temp_index].recv_buffer, recv_size, &ox_request_list[temp_index].recv_ox);
		ox_request_list[temp_index].recv_size = recv_size;

//		printQueue(&q_sent);
		dequeue_an_entry(&q_sent, temp_index);
		enqueue(&q_responded, temp_index);

		sem_post(&ox_request_list[temp_index].sem_wait);
		break;
	}
	temp = temp->next;
    }

    pthread_mutex_unlock(&ox_request_list_lock);

    if (temp) return temp_index;
    else {
PRINT_LINE("received packet(seq_num %x) has no matched request packet\n", seq_num);
	    return -1;
    }
}


// free an ox_request
int free_ox_request(int request_idx)
{
    PRINT_LINE("idx=%d\n", request_idx);
    pthread_mutex_lock(&ox_request_list_lock);

    dequeue_an_entry(&q_responded, request_idx);
    enqueue(&q_free, request_idx);

    pthread_mutex_unlock(&ox_request_list_lock);
}

// get a request from ox_request_list and send to the endpoint.
void *oxmem_send_thread(void *arg)
{
    struct oxmem_info_struct *oxmem_info =
	(struct oxmem_info_struct *) arg;
    int sockfd = oxmem_info->sockfd;
    int ox_request_idx;

    while (1) {
	sem_wait(&send_thread_wait);
	ox_request_idx = get_next_ox_request();
	PRINT_LINE("1SEND ox_request_idx = %d\n", ox_request_idx);
	if (ox_request_idx < 0) {
	    continue;
	}

	send(sockfd, ox_request_list[ox_request_idx].send_buffer,
	     ox_request_list[ox_request_idx].send_size, 0);
	PRINT_LINE("2SEND ox_request_idx = %d sent\n", ox_request_idx);
    }

    return NULL;
}

// receive response from the endpoint and save response to the
// ox_request_list
void *oxmem_recv_thread(void *arg)
{
    struct oxmem_info_struct *oxmem_info =
	(struct oxmem_info_struct *) arg;
    int sockfd = oxmem_info->sockfd;
    char recv_buffer[BUFFER_SIZE];
    int recv_size = 0;
    struct ox_packet_struct recv_ox_p;
    int ox_request_idx;
    int connection_id;
    int seq_num;

    while (1) {
PRINT_LINE("receving...\n");
	recv_size = recv(sockfd, recv_buffer, BUFFER_SIZE, 0);
PRINT_LINE("recv_size = %d\n", recv_size);

	if (recv_size > 0) {
	    struct ethhdr *etherHeader = (struct ethhdr *) recv_buffer;
	    if (etherHeader->h_proto != OX_ETHERTYPE)
		continue;
	} else {
	    continue;
	}

	packet_to_ox_struct(recv_buffer, recv_size, &recv_ox_p);

	connection_id = get_connection(&recv_ox_p);
	seq_num = recv_ox_p.tloe_hdr.seq_num_ack;

//update seq_num_ack
        update_seq_num_expected(connection_id, &recv_ox_p);

	ox_request_idx =
	    add_response_ox_request(connection_id, seq_num, recv_buffer,
				    recv_size, (recv_ox_p.tl_msg_mask) ? 1 : 0);

	recv_size = 0;

    }

    return NULL;
}
