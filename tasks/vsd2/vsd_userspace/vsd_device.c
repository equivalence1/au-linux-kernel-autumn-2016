#include "vsd_device.h"
#include <vsd_ioctl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#define PAGE_ALIGNED(size) (size % getpagesize() == 0)

static int fd = 0;
static const char *dev_file = "/dev/vsd";

int vsd_init()
{
    if (fd > 0)
        return 0;
    if ((fd = open(dev_file, O_RDWR)) < 0)
        return -1;
    return 0;
}

int vsd_deinit()
{
    close(fd);
    return 0;
}

static inline
int get_size(int fd, vsd_ioctl_get_size_arg_t *size)
{
    return ioctl(fd, VSD_IOCTL_GET_SIZE, size);
}

int vsd_get_size(size_t *out_size)
{
    if (fd <= 0)
        return -1;
	vsd_ioctl_get_size_arg_t size;
    int ret = get_size(fd, &size);
	*out_size = size.size;
    return ret;
}

static inline
int set_size(int fd, vsd_ioctl_set_size_arg_t *size)
{
    return ioctl(fd, VSD_IOCTL_SET_SIZE, size);
}

int vsd_set_size(size_t size)
{
    if (fd <= 0)
        return -1;
	vsd_ioctl_set_size_arg_t ioctl_size = {.size = size};
    int ret = set_size(fd, &ioctl_size);
    return ret;
}

ssize_t vsd_read(char* dst, off_t offset, size_t size)
{
    if (fd <= 0)
        return -1;
    if (lseek(fd, offset, SEEK_SET) == -1)
        return -1;
    return read(fd, dst, size);
}

ssize_t vsd_write(const char* src, off_t offset, size_t size)
{
    if (fd <= 0)
        return -1;
    if (lseek(fd, offset, SEEK_SET) == -1)
        return -1;
    return write(fd, src, size); 
}

void* vsd_mmap(size_t offset)
{
    size_t *cur_size;
    if (!PAGE_ALIGNED(offset))
        return NULL;
    if (fd <= 0)
        return NULL;
    if (vsd_get_size(cur_size) != 0)
        return NULL;
    return mmap(NULL, *cur_size - offset, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset); 
}

int vsd_munmap(void* addr, size_t offset)
{
    if (fd <= 0)
        return -1;
    if (!PAGE_ALIGNED(offset))
        return -1;
    return munmap(addr, offset);
}
