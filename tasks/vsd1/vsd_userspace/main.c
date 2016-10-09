#include <vsd_ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * TODO parse command line arguments and call proper
 * VSD_IOCTL_* using C function 'ioctl' (see man ioctl).
 */

const char *dev_file = "/dev/vsd";

static inline
void print_usage()
{
    printf(
"$ vsd_userspace help\n\
prints this message\n\
\n\
$ vsd_userspace size_get\n\
executes VSD_IOCTL_GET_SIZE and prints obtained size to stdout.\n\
\n\
$ vsd_userspace size_set SIZE_IN_BYTES\n\
executes VSD_IOCTL_SET_SIZE with argument SIZE_IN_BYTES.\n"
    );
}

static inline
int get_size(int fd, vsd_ioctl_get_size_arg_t *size)
{
    return ioctl(fd, VSD_IOCTL_GET_SIZE, size);
}

static inline
int set_size(int fd, vsd_ioctl_set_size_arg_t *size)
{
    return ioctl(fd, VSD_IOCTL_SET_SIZE, size);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage();
        return EXIT_FAILURE;
    }
    
    int fd = open(dev_file, 0);
    if (fd < 0) {
        printf("Could not get file descriptor for %s\n", dev_file);
        return EXIT_FAILURE;
    }

    const char *arg = argv[1];

    if (argc == 2 && !strcmp("help", arg)) {
        print_usage();
        goto success;
    }

    if (argc == 2 && !strcmp("size_get", arg)) {
        vsd_ioctl_get_size_arg_t size;
        int ret = get_size(fd, &size);
        if (ret < 0) {
            printf("Error while getting size\n");
            goto error;
        } else {
            printf("Size is %lu\n", size.size);
            goto success;
        }
    }

    if (argc == 3 && !strcmp("size_set", arg)) {
        vsd_ioctl_set_size_arg_t size = {.size = atoi(argv[2])};
        if (size.size == 0 && strcmp("0", argv[2]))
            goto error;
        int ret = set_size(fd, &size);
        if (ret < 0) {
            printf("Error while setting size\n");
            goto error;
        } else {
            printf("Size set to %lu\n", size.size);
            goto success;
        }
    }

success:
    close(fd);
    return EXIT_SUCCESS;
error:
    close(fd);
    return EXIT_FAILURE;
}
