#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <semaphore.h>
#include <limits.h>
#include "lib-ox-packet.h"
#include "lib-queue.h"

#define DAX_BUFFER_SIZE (1024 * 1024 * 16)  // 16MB buffer
#define PAGE_SIZE 4096
#define MAX_MAPPINGS 1024

static const char *oxmem_path = "/data";

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

struct page_mapping {
    off_t file_offset;
    void *buffer_addr;
    int dirty;
    time_t last_access;
};

struct dax_fs {
    void *buffer;
    size_t buffer_size;
    size_t file_size;
    pthread_mutex_t lock;
    struct page_mapping mappings[MAX_MAPPINGS];
    int mapping_count;
    void *mmap_base;
    size_t mmap_size;
    time_t mount_time;
    time_t file_mtime;
    
    // Network components from oxmem-fuse.c
    struct oxmem_info_struct oxmem_info;
    struct ox_request ox_request_list[OX_REQUEST_LIST_LENGTH];
    pthread_mutex_t ox_request_list_lock;
    sem_t send_thread_wait;
    sem_t post_queue_wait;
    Queue q_free, q_posted, q_sent, q_responded;
};

static struct dax_fs fs_data;

// Function declarations
void *oxmem_send_thread(void *arg);
void *oxmem_recv_thread(void *arg);
int try_to_post_ox_request(int connection_id, struct ox_packet_struct *ox_p, int expect_tl_msg);
int post_ox_request(int connection_id, struct ox_packet_struct *ox_p, int expect_tl_msg, char * target_buf);
int free_ox_request(int request_idx);
int get_next_ox_request(void);
int add_response_ox_request(int connection_id, int seq_num, char *recv_buffer, int recv_size, int tl_msg_included);
static int copy_recv_data_to_buf(char * target_buf, struct ox_request * ox_req);
static void show_help(const char *progname);
static int init_ox_request_list(void);
static int init_ox_request_queues(void);
void destroy_ox_request_list(void);

static void sigbus_handler(int sig, siginfo_t *info, void *context)
{
    (void) sig;
    (void) context;
    
    void *fault_addr = info->si_addr;
    
    if (fault_addr < fs_data.mmap_base || 
        fault_addr >= fs_data.mmap_base + fs_data.mmap_size) {
        exit(1);
    }
    
    pthread_mutex_lock(&fs_data.lock);
    
    off_t offset = (char*)fault_addr - (char*)fs_data.mmap_base;
    off_t page_offset = (offset / PAGE_SIZE) * PAGE_SIZE;
    
    int mapping_idx = -1;
    for (int i = 0; i < fs_data.mapping_count; i++) {
        if (fs_data.mappings[i].file_offset == page_offset) {
            mapping_idx = i;
            break;
        }
    }
    
    if (mapping_idx == -1 && fs_data.mapping_count < MAX_MAPPINGS) {
        mapping_idx = fs_data.mapping_count++;
        fs_data.mappings[mapping_idx].file_offset = page_offset;
        fs_data.mappings[mapping_idx].buffer_addr = 
            fs_data.buffer + (mapping_idx * PAGE_SIZE);
        fs_data.mappings[mapping_idx].dirty = 0;
    }
    
    if (mapping_idx >= 0) {
        // For network-based access, we don't read from file descriptor
        // This sigbus_handler needs to be updated for network access
        ssize_t bytes_read = 0; // TODO: implement network-based page loading
        // pread(fs_data.fd, fs_data.mappings[mapping_idx].buffer_addr, PAGE_SIZE, page_offset);
        
        if (bytes_read >= 0) {
            void *page_addr = fs_data.mmap_base + page_offset;
            mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_WRITE);
            memcpy(page_addr, fs_data.mappings[mapping_idx].buffer_addr, 
                   bytes_read < PAGE_SIZE ? bytes_read : PAGE_SIZE);
            fs_data.mappings[mapping_idx].last_access = time(NULL);
        }
    }
    
    pthread_mutex_unlock(&fs_data.lock);
}

static int setup_mmap_region(size_t size)
{
    fs_data.mmap_size = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
    
    fs_data.mmap_base = mmap(NULL, fs_data.mmap_size, PROT_NONE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fs_data.mmap_base == MAP_FAILED) {
        return -1;
    }
    
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = sigbus_handler;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGBUS, &sa, NULL) == -1) {
        munmap(fs_data.mmap_base, fs_data.mmap_size);
        return -1;
    }
    
    return 0;
}

static int dax_getattr(const char *path, struct stat *stbuf,
                       struct fuse_file_info *fi)
{
    (void) fi;
    int res = 0;
    struct stat *st = &fs_data.oxmem_info.st;

    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        stbuf->st_ino = 1;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        stbuf->st_atime = fs_data.mount_time;
        stbuf->st_mtime = fs_data.mount_time;
        stbuf->st_ctime = fs_data.mount_time;
        stbuf->st_size = 4096;
    } else if (strcmp(path, "/data") == 0) {
        stbuf->st_uid = st->st_uid;
        stbuf->st_gid = st->st_gid;
        stbuf->st_mode = S_IFREG | 0666;
        stbuf->st_nlink = 1;
        memcpy(&(stbuf->st_atim), &st->st_atim, sizeof(struct timespec));
        memcpy(&(stbuf->st_mtim), &st->st_mtim, sizeof(struct timespec));
        memcpy(&(stbuf->st_ctim), &st->st_ctim, sizeof(struct timespec));
        stbuf->st_size = st->st_size;
        stbuf->st_ino = 2;
    } else {
        res = -ENOENT;
    }

    return res;
}

static int dax_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags)
{
    (void) offset;
    (void) flags;

    // Handle nullpath case - use file info to determine path
    if (path == NULL) {
        if (fi == NULL) {
                return -ENOENT;
        }
        // Assume root directory if path is NULL
        path = "/";
    }

    if (strcmp(path, "/") != 0)
        return -ENOENT;

    struct stat st;
    
    // Add "." entry
    memset(&st, 0, sizeof(st));
    st.st_ino = 1;
    st.st_mode = S_IFDIR | 0755;
    st.st_uid = getuid();
    st.st_gid = getgid();
    st.st_atime = st.st_mtime = st.st_ctime = fs_data.mount_time;
    filler(buf, ".", &st, 0, 0);
    
    // Add ".." entry  
    memset(&st, 0, sizeof(st));
    st.st_ino = 1;
    st.st_mode = S_IFDIR | 0755;
    st.st_uid = getuid();
    st.st_gid = getgid();
    st.st_atime = st.st_mtime = st.st_ctime = fs_data.mount_time;
    filler(buf, "..", &st, 0, 0);
    
    // Add "data" entry
    memset(&st, 0, sizeof(st));
    st.st_ino = 2;
    st.st_mode = S_IFREG | 0666;
    st.st_uid = getuid();
    st.st_gid = getgid();
    pthread_mutex_lock(&fs_data.lock);
    st.st_size = fs_data.file_size;
    st.st_atime = time(NULL);
    st.st_mtime = fs_data.file_mtime;
    st.st_ctime = fs_data.mount_time;
    pthread_mutex_unlock(&fs_data.lock);
    filler(buf, "data", &st, 0, 0);

    return 0;
}

static int dax_open(const char *path, struct fuse_file_info *fi)
{
    if (strcmp(path, "/data") != 0)
        return -ENOENT;

    if ((fi->flags & O_ACCMODE) != O_RDONLY &&
        (fi->flags & O_ACCMODE) != O_RDWR &&
        (fi->flags & O_ACCMODE) != O_WRONLY)
        return -EACCES;

    // Set direct I/O to allow mmap MAP_SHARED possibility
    //fi->direct_io = FUSE_DIRECT_IO;

    // Connection should already be established
    if (fs_data.oxmem_info.connection_id < 0) {
        return -ENXIO;
    }

    return 0;
}

static int dax_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    (void) fi;
    
    if (strcmp(path, "/data") != 0)
        return -ENOENT;

    printf("READ 0x%lx %ld\n", offset, size);

    if (offset + size > fs_data.oxmem_info.st.st_size) {
        printf("READ %s %d offset=%lu oxmem_info.st.st_size=%lu\n", path,
               __LINE__, offset, fs_data.oxmem_info.st.st_size);
        return -ENXIO;
    }

    if (fs_data.oxmem_info.connection_id < 0) {
        printf("READ %s %d \n", path, __LINE__);
        return -ENXIO;
    }

    struct ox_packet_struct send_ox_p;
    uint64_t send_flits[256];
    long int remain_size = size, read_size;
    int idx[4096] = { -1, };
    int temp_idx;
    int j = 0;
    char * temp_target_buf;

    while (remain_size > 0) {
        read_size = (remain_size > READ_WRITE_UNIT) ? READ_WRITE_UNIT : remain_size;
        for (int i = 10; i >= 0; i--) {
            if (read_size >= (1 << i)) {
                read_size = 1 << i;
                break;
            }
        }

        bzero(send_flits, 2048);
        make_get_op_packet(fs_data.oxmem_info.connection_id, read_size,
                           offset + (size - remain_size), &send_ox_p,
                           send_flits);

        temp_target_buf = buf + (size - remain_size);

        do {
            temp_idx = post_ox_request(fs_data.oxmem_info.connection_id, &send_ox_p, 1, temp_target_buf);

            if (temp_idx < 0) {
                for (int i = 0; i < j; i++) {
                    if (idx[i] < 0)
                        continue;
                    if (0 == sem_trywait(&fs_data.ox_request_list[idx[i]].sem_wait)) {
                        copy_recv_data_to_buf(fs_data.ox_request_list[idx[i]].target_buf, &fs_data.ox_request_list[idx[i]]);
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
    for (int i = 0; i < j; i++) {
        if (idx[i] < 0)
            continue;
        sem_wait(&fs_data.ox_request_list[idx[i]].sem_wait);
        copy_recv_data_to_buf(fs_data.ox_request_list[idx[i]].target_buf, &fs_data.ox_request_list[idx[i]]);
        free_ox_request(idx[i]);
        idx[i] = -1;
    }

    return size;
}

static int dax_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    (void) fi;
    
    if (strcmp(path, "/data") != 0)
        return -ENOENT;

//    printf("WRITE 0x%lx %ld\n", offset, size);

    if (offset + size > fs_data.oxmem_info.st.st_size)
        return -ENXIO;

    struct ox_packet_struct send_ox_p;
    uint64_t send_flits[256];
    long int remain_size = size, write_size;
    int idx[4096] = { -1, };
    int temp_idx;
    int j = 0;

    while (remain_size > 0) {
        write_size = (remain_size > READ_WRITE_UNIT) ? READ_WRITE_UNIT : remain_size;

        for (int i = 10; i >= 0; i--) {
            if (write_size >= (1 << i)) {
                write_size = 1 << i;
                break;
            }
        }

        make_putfull_op_packet(fs_data.oxmem_info.connection_id,
                               buf + (size - remain_size), write_size,
                               offset + (size - remain_size), &send_ox_p,
                               send_flits);

        do {
            temp_idx = post_ox_request(fs_data.oxmem_info.connection_id, &send_ox_p, 1, NULL);

            if (temp_idx < 0) {
                for (int i = 0; i < j; i++) {
                    if (idx[i] < 0)
                        continue;
                    if (0 == sem_trywait(&fs_data.ox_request_list[idx[i]].sem_wait)) {
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
    for (int i = 0; i < j; i++) {
        if (idx[i] < 0)
            continue;
        sem_wait(&fs_data.ox_request_list[idx[i]].sem_wait);
        free_ox_request(idx[i]);
        idx[i] = -1;
    }

    return size;
}

static int dax_truncate(const char *path, off_t size,
                        struct fuse_file_info *fi)
{
    (void) fi;
    
    if (strcmp(path, "/data") != 0)
        return -ENOENT;

    // For network-based access, we don't actually truncate
    // but update our size information
    if (size > fs_data.oxmem_info.st.st_size)
        return -ENXIO;
    
    fs_data.file_mtime = time(NULL);
    
    return 0;
}

static int dax_flush(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    (void) fi;
    
    // For network-based access, no explicit sync needed
    return 0;
}

/*
static void *dax_mmap(const char *path, size_t length, int prot, int flags,
                      off_t offset, struct fuse_file_info *fi)
{
    (void) fi;
    (void) prot;
    (void) flags;
    
    if (strcmp(path, "/data") != 0)
        return MAP_FAILED;
    
    if (offset + length > fs_data.file_size) {
        if (ftruncate(fs_data.fd, offset + length) < 0)
            return MAP_FAILED;
        fs_data.file_size = offset + length;
    }
    
    if (fs_data.mmap_base == NULL) {
        if (setup_mmap_region(fs_data.file_size) < 0)
            return MAP_FAILED;
    }
    
    return fs_data.mmap_base + offset;
}
*/

static void show_help(const char *progname)
{
    printf("usage: %s [options] <mountpoint>\n\n", progname);
    printf("File-system specific options (REQUIRED):\n"
           "    --netdev=DEV        Ethernet interface to use (REQUIRED)\n"
           "    --mac=MAC           MAC address of OX mem endpoint (REQUIRED)\n"
           "    --size=N            Size in MB of OX mem endpoint (REQUIRED)\n\n"
           "Optional arguments:\n"
           "    --base=ADDR         Base address (default: \"0x0\")\n"
           "    -h, --help          Show this help message\n\n"
           "Example:\n"
           "    %s --netdev=eth0 --mac=aa:bb:cc:dd:ee:ff --size=1024 /mnt/oxmem\n\n", progname);
}

void destroy_ox_request_list(void)
{
    pthread_mutex_destroy(&fs_data.ox_request_list_lock);
}

static int init_ox_request_list(void)
{
    int i;

    bzero(fs_data.ox_request_list,
          sizeof(struct ox_request) * OX_REQUEST_LIST_LENGTH);

    for (i = 0; i < OX_REQUEST_LIST_LENGTH; i++) {
        fs_data.ox_request_list[i].connection_id = -1;
        fs_data.ox_request_list[i].seq_num = -1;
        fs_data.ox_request_list[i].target_buf = NULL;
        sem_init(&fs_data.ox_request_list[i].sem_wait, 0, 1);
    }

    if (pthread_mutex_init(&fs_data.ox_request_list_lock, NULL) != 0) {
        printf("\n mutex init has failed\n");
        return 1;
    }

    sem_init(&fs_data.send_thread_wait, 0, 1);
    sem_init(&fs_data.post_queue_wait, 0, 1);

    return 0;
}

static int init_ox_request_queues(void)
{
    int i;

    initQueue(&fs_data.q_free);
    initQueue(&fs_data.q_posted);
    initQueue(&fs_data.q_sent);
    initQueue(&fs_data.q_responded);

    for(i=0; i<OX_REQUEST_LIST_LENGTH; i++) {
        enqueue(&fs_data.q_free, i);
    }

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

    for (i=0; i<64; i++) {
        if ( (tl_msg_mask >> i) & 0x1 == 1) break;
    }

    be64_temp = be64toh(ox_req->recv_ox.flits[i]);
    memcpy(&(tl_msg_ack), &be64_temp, sizeof(uint64_t));
    memcpy(target_buf, &ox_req->recv_ox.flits[i+1], 1 << tl_msg_ack.size);
    return 1 << tl_msg_ack.size;
}

int post_ox_request(int connection_id, struct ox_packet_struct *ox_p, int expect_tl_msg, char * target_buf)
{
    int i, index;

    pthread_mutex_lock(&fs_data.ox_request_list_lock);

    index = dequeue(&fs_data.q_free);

    if( index >= 0 ) {
        fs_data.ox_request_list[index].connection_id = connection_id;
        fs_data.ox_request_list[index].expect_tl_msg = expect_tl_msg;
        memcpy(&fs_data.ox_request_list[index].send_ox, ox_p, sizeof(struct ox_packet_struct));
        set_seq_num_to_ox_packet(fs_data.ox_request_list[index].connection_id, &fs_data.ox_request_list[index].send_ox);
        fs_data.ox_request_list[index].seq_num = fs_data.ox_request_list[index].send_ox.tloe_hdr.seq_num;
        fs_data.ox_request_list[index].target_buf = target_buf;

        ox_struct_to_packet(&fs_data.ox_request_list[index].send_ox, fs_data.ox_request_list[index].send_buffer, &fs_data.ox_request_list[index].send_size);

        sem_init(&fs_data.ox_request_list[index].sem_wait, 0, 0);
        enqueue(&fs_data.q_posted, index);
        sem_post(&fs_data.send_thread_wait);
    }

    pthread_mutex_unlock(&fs_data.ox_request_list_lock);

    return index;
}

int get_next_ox_request(void)
{
    int i, index=0;

    pthread_mutex_lock(&fs_data.ox_request_list_lock);

    index = dequeue(&fs_data.q_posted);

    if( index >= 0 ) {
        enqueue(&fs_data.q_sent, index);
    }

    pthread_mutex_unlock(&fs_data.ox_request_list_lock);

    return index;
}

int add_response_ox_request(int connection_id, int seq_num, char *recv_buffer, int recv_size, int tl_msg_included)
{
    int i, temp_index;
    Node * temp = NULL;

    pthread_mutex_lock(&fs_data.ox_request_list_lock);

    temp = fs_data.q_sent.front;
    while (temp) {
        temp_index = temp->data;
        if ( temp_index >= 0
            && fs_data.ox_request_list[temp_index].seq_num == seq_num
            && fs_data.ox_request_list[temp_index].connection_id == connection_id
            && fs_data.ox_request_list[temp_index].expect_tl_msg == tl_msg_included ) {
            
            memcpy(fs_data.ox_request_list[temp_index].recv_buffer, recv_buffer, recv_size);
            packet_to_ox_struct(fs_data.ox_request_list[temp_index].recv_buffer, recv_size, &fs_data.ox_request_list[temp_index].recv_ox);
            fs_data.ox_request_list[temp_index].recv_size = recv_size;

            dequeue_an_entry(&fs_data.q_sent, temp_index);
            enqueue(&fs_data.q_responded, temp_index);

            sem_post(&fs_data.ox_request_list[temp_index].sem_wait);
            break;
        }
        temp = temp->next;
    }

    pthread_mutex_unlock(&fs_data.ox_request_list_lock);

    if (temp) return temp_index;
    else return -1;
}

int free_ox_request(int request_idx)
{
    pthread_mutex_lock(&fs_data.ox_request_list_lock);

    dequeue_an_entry(&fs_data.q_responded, request_idx);
    enqueue(&fs_data.q_free, request_idx);

    pthread_mutex_unlock(&fs_data.ox_request_list_lock);
    return 0;
}

void *oxmem_send_thread(void *arg)
{
    struct dax_fs *dax_fs = (struct dax_fs *) arg;
    int sockfd = dax_fs->oxmem_info.sockfd;
    int ox_request_idx;

    while (1) {
        sem_wait(&dax_fs->send_thread_wait);
        ox_request_idx = get_next_ox_request();
        if (ox_request_idx < 0) {
            continue;
        }

        send(sockfd, dax_fs->ox_request_list[ox_request_idx].send_buffer,
             dax_fs->ox_request_list[ox_request_idx].send_size, 0);
    }

    return NULL;
}

void *oxmem_recv_thread(void *arg)
{
    struct dax_fs *dax_fs = (struct dax_fs *) arg;
    int sockfd = dax_fs->oxmem_info.sockfd;
    char recv_buffer[BUFFER_SIZE];
    int recv_size = 0;
    struct ox_packet_struct recv_ox_p;
    int ox_request_idx;
    int connection_id;
    int seq_num;

    while (1) {
        recv_size = recv(sockfd, recv_buffer, BUFFER_SIZE, 0);

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

        update_seq_num_expected(connection_id, &recv_ox_p);

        ox_request_idx = add_response_ox_request(connection_id, seq_num, recv_buffer,
                                                recv_size, (recv_ox_p.tl_msg_mask) ? 1 : 0);

        recv_size = 0;
    }

    return NULL;
}

static void *dax_init(struct fuse_conn_info *conn,
                      struct fuse_config *cfg)
{
    (void) conn;
    cfg->use_ino = 1;
    cfg->nullpath_ok = 0;  // Disable null paths
    cfg->direct_io = 0;    // Allow kernel caching
    cfg->kernel_cache = 1; // Enable kernel page cache
    cfg->auto_cache = 1;   // Enable automatic caching
    
    return NULL;
}

static struct fuse_operations dax_oper = {
    .getattr    = dax_getattr,
    .readdir    = dax_readdir,
    .open       = dax_open,
    .read       = dax_read,
    .write      = dax_write,
    .truncate   = dax_truncate,
    .flush      = dax_flush,
    .init       = dax_init,
};

int main(int argc, char *argv[])
{
    int ret;
    int i;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    uint32_t mac_values[6];
    struct sockaddr_ll saddr;
    pthread_t recv_thread, send_thread;
    int recv_thread_id, recv_thread_status, send_thread_id, send_thread_status;
    char *end;

    // Initialize options to NULL - no defaults for required arguments
    options.netdev = NULL;
    options.mac = NULL;
    options.size = NULL;
    options.base = strdup("0x0");  // Keep base as it has a reasonable default

    // Parse options
    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
        return 1;

    if (options.show_help) {
        show_help(argv[0]);
        assert(fuse_opt_add_arg(&args, "--help") == 0);
        args.argv[0][0] = '\0';
    } else {
        // Validate required arguments (only if not showing help)
        int missing_args = 0;
        if (!options.netdev) {
            fprintf(stderr, "[ERROR] Missing required argument: --netdev (network device)\n");
            missing_args = 1;
        }
        if (!options.mac) {
            fprintf(stderr, "[ERROR] Missing required argument: --mac (MAC address)\n");
            missing_args = 1;
        }
        if (!options.size) {
            fprintf(stderr, "[ERROR] Missing required argument: --size (memory size in MB)\n");
            missing_args = 1;
        }

        if (missing_args) {
            fprintf(stderr, "[ERROR] Required arguments are missing. Use --help for usage information.\n");
            return 1;
        }
    }

    // Initialize fs_data structure
    fs_data.buffer = mmap(NULL, DAX_BUFFER_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fs_data.buffer == MAP_FAILED) {
        perror("mmap buffer");
        return 1;
    }
    fs_data.buffer_size = DAX_BUFFER_SIZE;
    fs_data.mapping_count = 0;
    fs_data.mmap_base = NULL;
    fs_data.mount_time = time(NULL);
    fs_data.file_mtime = fs_data.mount_time;

    if (pthread_mutex_init(&fs_data.lock, NULL) != 0) {
        perror("mutex init");
        munmap(fs_data.buffer, fs_data.buffer_size);
        return 1;
    }

    // Configure oxmem_info
    strcpy(fs_data.oxmem_info.netdev, options.netdev);
    fs_data.oxmem_info.netdev_id = if_nametoindex(options.netdev);
    if (fs_data.oxmem_info.netdev_id == 0) {
        printf("netdev = %s is not valid.\n", options.netdev);
        return -1;
    }

    if (6 == sscanf(options.mac, "%2x:%2x:%2x:%2x:%2x:%2x", &mac_values[0],
                    &mac_values[1], &mac_values[2], &mac_values[3],
                    &mac_values[4], &mac_values[5])) {
        for (i = 0; i < 6; i++)
            fs_data.oxmem_info.mac_addr += (uint64_t) mac_values[i] << (i * 8);
    } else {
        printf("MAC value is not valid - %s\n", options.mac);
        return -1;
    }

    fs_data.oxmem_info.base = strtoull(options.base, &end, 16);
    if (end == options.base) {
        printf("--base=%s is invalid hex digit.\n", options.base);
        return -1;
    } else if (fs_data.oxmem_info.base == ULLONG_MAX) {
        printf("--base=%s is too big.\n", options.base);
        return -1;
    }

    // oxmem stat
    fs_data.oxmem_info.st.st_mode = 0555;
    fs_data.oxmem_info.st.st_uid = getuid();
    fs_data.oxmem_info.st.st_gid = getgid();
    clock_gettime(CLOCK_REALTIME, &fs_data.oxmem_info.st.st_atim);
    clock_gettime(CLOCK_REALTIME, &fs_data.oxmem_info.st.st_mtim);
    clock_gettime(CLOCK_REALTIME, &fs_data.oxmem_info.st.st_ctim);
    fs_data.oxmem_info.st.st_size = fs_data.oxmem_info.size = atol(options.size) * 1024 * 1024;
    fs_data.file_size = fs_data.oxmem_info.size;
    fs_data.oxmem_info.connection_id = -1;

    // Create RAW socket
    fs_data.oxmem_info.sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fs_data.oxmem_info.sockfd == -1) {
        printf("Socket creation error.\n");
        fs_data.oxmem_info.sockfd = 0;
        return -ENOENT;
    }

    bzero(&saddr, sizeof(struct sockaddr_ll));
    saddr.sll_family = AF_PACKET;
    saddr.sll_protocol = htons(ETH_P_ALL);
    saddr.sll_ifindex = fs_data.oxmem_info.netdev_id;

    // bind with interface
    if (bind(fs_data.oxmem_info.sockfd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        printf("Socket bind error\n");
        close(fs_data.oxmem_info.sockfd);
        return -errno;
    }

    // init ox_request_list
    if (0 != init_ox_request_list()) {
        printf("init_ox_request_list() error\n");
        ret = -errno;
    }

    // init ox_request queues
    if (0 != init_ox_request_queues()) {
        printf("init_ox_request_queues() error\n");
        ret = -errno;
    }

    // Create send/recv thread
    recv_thread_id = pthread_create(&recv_thread, NULL, oxmem_recv_thread, (void *) &fs_data);
    if (recv_thread_id < 0) {
        printf("Thread creation fail\n");
        return -1;
    }

    send_thread_id = pthread_create(&send_thread, NULL, oxmem_send_thread, (void *) &fs_data);
    if (send_thread_id < 0) {
        printf("Thread creation fail\n");
        return -1;
    }

    // Connection setup
    struct ox_packet_struct send_ox_p;
    int idx;
    //for channel A
    fs_data.oxmem_info.connection_id = make_open_connection_packet(fs_data.oxmem_info.sockfd, fs_data.oxmem_info.netdev,
                                                                  fs_data.oxmem_info.mac_addr, &send_ox_p);

    idx = post_ox_request(fs_data.oxmem_info.connection_id, &send_ox_p, 0, NULL);
    sem_wait(&fs_data.ox_request_list[idx].sem_wait);
    free_ox_request(idx);

    //for channel D
    send_ox_p.tloe_hdr.msg_type = NORMAL;
    send_ox_p.tloe_hdr.chan = CHANNEL_D;

    idx = post_ox_request(fs_data.oxmem_info.connection_id, &send_ox_p, 0, NULL);
    sem_wait(&fs_data.ox_request_list[idx].sem_wait);
    free_ox_request(idx);

    ret = fuse_main(args.argc, args.argv, &dax_oper, NULL);

    // Connection cleanup
    make_close_connection_packet(fs_data.oxmem_info.connection_id, &send_ox_p);
    idx = post_ox_request(fs_data.oxmem_info.connection_id, &send_ox_p, 0, NULL);
    sem_wait(&fs_data.ox_request_list[idx].sem_wait);
    free_ox_request(idx);

    delete_connection(fs_data.oxmem_info.connection_id);
    fs_data.oxmem_info.connection_id = -1;

    fuse_opt_free_args(&args);

    // Cleanup
    destroy_ox_request_list();
    close(fs_data.oxmem_info.sockfd);
    pthread_mutex_destroy(&fs_data.lock);
    munmap(fs_data.buffer, fs_data.buffer_size);
    if (fs_data.mmap_base)
        munmap(fs_data.mmap_base, fs_data.mmap_size);

    return ret;
}
