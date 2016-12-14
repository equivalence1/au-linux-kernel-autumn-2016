#include <mutex.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static const char *mutex_device = "/dev/mutex";

static int fd = 0;

mutex_err_t mutex_init(mutex_t *m)
{
    int ret;
    mutex_ioctl_arg_t arg;

    // userspace side
    shared_spinlock_init(&m->lock);
    shared_spinlock_init(&m->queue_lock);
    m->wqueue_size = 0;
    // kernel side
    arg.id = (size_t)m;
    ret = ioctl(fd, MUTEX_IOCTL_LOCK_CREATE, &arg);

    if (ret == 0)
        return MUTEX_OK;
    else
        return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_deinit(mutex_t *m)
{
    int ret;
    mutex_ioctl_arg_t arg;
    // userspace side
    shared_spin_lock(&m->queue_lock);
    if (m->wqueue_size > 0)
        return MUTEX_INTERNAL_ERR;
    // kernel side
    arg.id = (size_t)m;
    ret = ioctl(fd, MUTEX_IOCTL_LOCK_DESTROY, &arg);

    if (ret == 0)
        return MUTEX_OK;
    else
        return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_lock(mutex_t *m)
{
    int ret;
    mutex_ioctl_arg_t arg;

    ret = 0;
    arg.id = (size_t)m;

    while ((!shared_spin_trylock(&m->lock)) && (ret == 0)) {
        shared_spin_lock(&m->queue_lock);
        m->wqueue_size++;
        shared_spin_unlock(&m->queue_lock);

        ret = ioctl(fd, MUTEX_IOCTL_LOCK, &arg);

        shared_spin_lock(&m->queue_lock);
        m->wqueue_size--;
        shared_spin_unlock(&m->queue_lock);
    }

    if (ret == 0)
        return MUTEX_OK;
    else
        return MUTEX_INTERNAL_ERR;
}

mutex_err_t mutex_unlock(mutex_t *m)
{
    int ret;
    mutex_ioctl_arg_t arg;

    arg.id = (size_t)m;

    shared_spin_unlock(&m->lock);

    shared_spin_lock(&m->queue_lock);
        if (m->wqueue_size != 0) {
        ret = ioctl(fd, MUTEX_IOCTL_UNLOCK, &arg);
        if (ret != 0) {
            shared_spin_unlock(&m->queue_lock);
            return MUTEX_INTERNAL_ERR;
        }
    }
    shared_spin_unlock(&m->queue_lock);

    return MUTEX_OK;
}

mutex_err_t mutex_lib_init()
{
    if (fd > 0)
        return MUTEX_INTERNAL_ERR;

    if ((fd = open(mutex_device, O_RDWR)) < 0)
        return MUTEX_INTERNAL_ERR;

    return MUTEX_OK;
}

mutex_err_t mutex_lib_deinit()
{
    if (fd <= 0)
        return MUTEX_INTERNAL_ERR;

    if ((fd = close(fd)) < 0)
        return MUTEX_INTERNAL_ERR;

    return MUTEX_OK;
}
