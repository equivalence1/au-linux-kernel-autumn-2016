#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include "mutex_ioctl.h"

#define LOG_TAG "[MUTEX_MODULE] "

typedef struct system_mutex_state {
    // lock only when adding new tgroup
    spinlock_t wlock;
    struct hlist_head tgstates;
} system_mutex_state_t;

typedef struct process_mutex_state {
    int pid;                            // pid of process
    spinlock_t wlock;                   // lock for adding/deleting mutexes
    struct hlist_node tgstates;         // list of processes' states
    struct hlist_head mutexes;          // list of mutexes for this process
} process_mutex_state_t;

typedef struct process_mutex {
    size_t id;                             // id of this mutex in corresponding process
    wait_queue_head_t waiting_threads;     // threads which are waiting for this mutex to unlock
    struct hlist_node mutexes;             // list of mutexes for this process

    volatile int status; // 1 -- locked, 0 -- unlocked, < 0 -- error
} process_mutex_t;

typedef struct mutex_dev {
    struct miscdevice mdev;
    system_mutex_state_t sysmstate;
} mutex_dev_t;

static mutex_dev_t *mutex_dev;

// ============================ MUTEX STATES LOGIC ============================

static inline void init_system_mutex_state(system_mutex_state_t *sysmstate)
{
    spin_lock_init(&sysmstate->wlock);
    INIT_HLIST_HEAD(&sysmstate->tgstates);
}

static inline void init_process_mutex_state(process_mutex_state_t *procmstate, int pid)
{
    procmstate->pid = pid;
    spin_lock_init(&procmstate->wlock);
    INIT_HLIST_NODE(&procmstate->tgstates);
    INIT_HLIST_HEAD(&procmstate->mutexes);
}

static void deinit_system_mutex_state(system_mutex_state_t *sysmstate)
{
    // This is called on module release. So no opened file descriptors
    // exist. Thus we have nothing to cleanup here
}

static int init_process_state(int pid)
{
    // We don't check here that mutexes for this pid already initialized.
    // It's too time-consuming and it's easier to check in user-space lib
    
    process_mutex_state_t *process_mutex_state;
    process_mutex_state = (process_mutex_state_t *)kmalloc(sizeof(process_mutex_state_t), GFP_KERNEL);
    if (process_mutex_state == NULL)
        return -ENOMEM;
    init_process_mutex_state(process_mutex_state, pid);


    spin_lock(&mutex_dev->sysmstate.wlock);
    hlist_add_head_rcu(&process_mutex_state->tgstates, &mutex_dev->sysmstate.tgstates);
    spin_unlock(&mutex_dev->sysmstate.wlock);

    return 0;
}

static process_mutex_state_t* find_state(int pid) {
    process_mutex_state_t *state = NULL;

    hlist_for_each_entry_rcu(state, &mutex_dev->sysmstate.tgstates, tgstates) {
        if (state->pid == pid)
            break;
    }

    return state;
}

static process_mutex_t* find_mutex(int pid, size_t id) {
    process_mutex_state_t *state = find_state(pid);
    process_mutex_t *mutex = NULL;

    if (state == NULL)
        return NULL;

    hlist_for_each_entry_rcu(mutex, &state->mutexes, mutexes) {
        if (mutex->id == id)
            break;
    }

    return mutex;
}

static int deinit_process_state(int pid)
{
    process_mutex_t *mutex;
    process_mutex_state_t *state = NULL;

    spin_lock(&mutex_dev->sysmstate.wlock);

    state = find_state(pid);
    if (state == NULL) {
        // Not sure for EBADF, but i think it fits better than EINTR and EIO
        spin_unlock(&mutex_dev->sysmstate.wlock);
        return -EBADF;
    }

    hlist_del_rcu(&state->tgstates);
    // Ok, we removed state from list. Now we should wait for readers and then free it
    spin_unlock(&mutex_dev->sysmstate.wlock);
    synchronize_rcu();


    hlist_for_each_entry(mutex, &state->mutexes, mutexes) {
        mutex->status = -1;
        wmb();
        wake_up_all(&mutex->waiting_threads);
        schedule();
        kfree(mutex);
    }
    kfree(state);

    return 0;
}

static int insert_mutex(int pid, process_mutex_t *m) {
    process_mutex_state_t *state;

    spin_lock(&mutex_dev->sysmstate.wlock);

    state = find_state(pid);
    if (state == NULL) {
        spin_unlock(&mutex_dev->sysmstate.wlock);
        return -EFAULT;
    }

    hlist_add_head_rcu(&m->mutexes, &state->mutexes);
    spin_unlock(&mutex_dev->sysmstate.wlock);

    return 0;
}

static process_mutex_t* remove_mutex(int pid, size_t id) {
    process_mutex_t *mutex;

    spin_lock(&mutex_dev->sysmstate.wlock);

    mutex = find_mutex(pid, id);
    if (mutex == NULL) {
        spin_unlock(&mutex_dev->sysmstate.wlock);
        return NULL;
    }

    hlist_del_rcu(&mutex->mutexes);

    spin_unlock(&mutex_dev->sysmstate.wlock);
    synchronize_rcu();

    mutex->status = -1;
    wmb();
    wake_up_all(&mutex->waiting_threads);
    schedule();

    return mutex;
}

// ============================ MUTEXES LOGIC ============================

static inline void init_process_mutex(process_mutex_t *mutex, size_t id)
{
    mutex->id = id;
    mutex->status = 0;
    init_waitqueue_head(&mutex->waiting_threads);
    INIT_HLIST_NODE(&mutex->mutexes);
}

static int create_mutex(int pid, mutex_ioctl_arg_t __user *uarg)
{
    mutex_ioctl_arg_t arg;
    process_mutex_t *mutex;

    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    mutex = kmalloc(sizeof(process_mutex_t), GFP_KERNEL);
    if (mutex == NULL)
        return -ENOMEM;
    init_process_mutex(mutex, arg.id);

    return insert_mutex(pid, mutex);
}

static int destroy_mutex(int pid, mutex_ioctl_arg_t __user *uarg) {
    mutex_ioctl_arg_t arg;
    process_mutex_t *mutex;

    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    mutex = remove_mutex(pid, arg.id);
    if (mutex == NULL)
        return -EFAULT;
    kfree(mutex);

    return 0;
}

static int wait_mutex(int pid, mutex_ioctl_arg_t __user *uarg)
{
    mutex_ioctl_arg_t arg;
    process_mutex_t *mutex;

    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    rcu_read_lock();
    mutex = find_mutex(pid, arg.id);

    if (mutex == NULL)
        return -EFAULT;
    rcu_read_unlock();

    mutex->status = 1;
    wait_event(mutex->waiting_threads, (mutex->status != 1));

    if (mutex->status < 0) 
        return -EFAULT;

    mutex->status = 1;

    return 0;
}

static int notify_mutex(int pid, mutex_ioctl_arg_t __user *uarg)
{
    mutex_ioctl_arg_t arg;
    process_mutex_t *mutex;

    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    rcu_read_lock();

    mutex = find_mutex(pid, arg.id);
    if (mutex == NULL) {
        rcu_read_unlock();
        return -EFAULT;
    }

    mutex->status = 0;
    wake_up(&mutex->waiting_threads);
    rcu_read_unlock();

    return 0;
}

// ============================ DRIVER LOGIC ============================

static int mutex_dev_open(struct inode *inode, struct file *filp)
{
    int ret = init_process_state(current->pid);
    if (ret == 0)
        pr_notice(LOG_TAG " opened successfully\n");
    return ret;
}

static int mutex_dev_release(struct inode *inode, struct file *filp)
{
    int ret = deinit_process_state(current->pid);
    if (ret == 0)
        pr_notice(LOG_TAG " closed\n");
    return ret;
}

static long mutex_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    int pid = task_tgid_vnr(current);
    switch(cmd) {
        case MUTEX_IOCTL_LOCK_CREATE:
            return create_mutex(pid, (mutex_ioctl_arg_t __user*)arg);
            break;
        case MUTEX_IOCTL_LOCK_DESTROY:
            return destroy_mutex(pid, (mutex_ioctl_arg_t __user*)arg);
            break;
        case MUTEX_IOCTL_LOCK:
            return wait_mutex(pid, (mutex_ioctl_arg_t __user*)arg);
            break;
        case MUTEX_IOCTL_UNLOCK:
            return notify_mutex(pid, (mutex_ioctl_arg_t __user*)arg);
            break;
        default:
            return -ENOTTY;
    }
}

static struct file_operations mutex_dev_fops = {
    .owner = THIS_MODULE,
    .open = mutex_dev_open,
    .release = mutex_dev_release,
    .unlocked_ioctl = mutex_dev_ioctl
};

static int __init mutex_module_init(void)
{
    int ret = 0;
    mutex_dev = (mutex_dev_t*)
        kzalloc(sizeof(*mutex_dev), GFP_KERNEL);
    if (!mutex_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    mutex_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    mutex_dev->mdev.name = "mutex";
    mutex_dev->mdev.fops = &mutex_dev_fops;
    mutex_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;
    init_system_mutex_state(&mutex_dev->sysmstate);

    if ((ret = misc_register(&mutex_dev->mdev)))
        goto error_misc_reg;

    pr_notice(LOG_TAG "Mutex dev with MINOR %u"
        " has started successfully\n", mutex_dev->mdev.minor);
    return 0;

error_misc_reg:
    kfree(mutex_dev);
    mutex_dev = NULL;
error_alloc:
    return ret;
}

static void __exit mutex_module_exit(void)
{
    pr_notice(LOG_TAG "Removing mutex device %s\n", mutex_dev->mdev.name);
    misc_deregister(&mutex_dev->mdev);
    deinit_system_mutex_state(&mutex_dev->sysmstate);
    kfree(mutex_dev);
    mutex_dev = NULL;
}

module_init(mutex_module_init);
module_exit(mutex_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU user space mutex kernel side support module");
MODULE_AUTHOR("Kernel hacker!");
