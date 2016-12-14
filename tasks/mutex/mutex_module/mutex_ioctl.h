#ifndef _MUTEX_UAPI_H
#define _MUTEX_UAPI_H

#ifdef __KERNEL__
#include <asm/ioctl.h>
#include "shared_spinlock.h"
#else
#include <sys/ioctl.h>
#include <stddef.h>
#include <shared_spinlock.h>
#endif //__KERNEL__

#define MUTEX_IOCTL_MAGIC 'M'

typedef size_t mutex_id_t;

// create kernel side of mutex with specified id which should be an address this mutex

typedef struct mutex_ioctl_arg {
    mutex_id_t id;
} mutex_ioctl_arg_t;

#define MUTEX_IOCTL_LOCK_CREATE \
    _IOW(MUTEX_IOCTL_MAGIC, 1, mutex_ioctl_arg_t)

// destroy kernel side of mutex
#define MUTEX_IOCTL_LOCK_DESTROY \
    _IOW(MUTEX_IOCTL_MAGIC, 2, mutex_ioctl_arg_t)

// lock mutex with specified id in kernel
#define MUTEX_IOCTL_LOCK \
    _IOW(MUTEX_IOCTL_MAGIC, 3, mutex_ioctl_arg_t)

// unlock mutex with specified id in kernel
#define MUTEX_IOCTL_UNLOCK \
    _IOW(MUTEX_IOCTL_MAGIC, 4, mutex_ioctl_arg_t)

#endif //_VSD_UAPI_H
