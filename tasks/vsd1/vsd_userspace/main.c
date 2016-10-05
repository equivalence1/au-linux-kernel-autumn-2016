#include <vsd_ioctl.h>
#include <stdio.h>
#include <string.h>
/*
 * TODO parse command line arguments and call proper
 * VSD_IOCTL_* using C function 'ioctl' (see man ioctl).
 */

void print_usage() {
    printf("
$ vsd_userspace help\n
выводит это\n
\n
$ vsd_userspace size_get\n
выполняет VSD_IOCTL_GET_SIZE и печатает полученный размер\n
в стандартный вывод.\n
\n
$ vsd_userspace size_set SIZE_IN_BYTES\n
выполняет VSD_IOCTL_SET_SIZE с аргументом SIZE_IN_BYTES.\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return EXIT_FAILURE;
    }

    const char *arg = argv[1];

    if (argc == 2 && !strcmp("help", arg)) {
        print_usage();
        return EXIT_SUCCESS;
    }

    if (argc == 2 && !strcmp("size_get", arg)) {

    }

    if (argc == 3 && !strcmp("size_set", arg)) {
        int size = atoi(argv[2]);
        if (size == 0 && strcmp("0", argv[2]))
            return EXIT_FAILURE;
        
    }

    return EXIT_FAILURE;
}
