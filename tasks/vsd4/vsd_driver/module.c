#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/platform_device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "../vsd_device/vsd_hw.h"
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

#define VSD_DEV_CMD_QUEUE_MAX_LEN 10
// TODO implement write syscall in synchronous non blocking mode.
// TODO implement poll, epoll, select syscalls using .poll file_operations func.

typedef vsd_hw_regs_t vsd_task_t;

typedef struct vsd_dev {
    struct miscdevice mdev;
    struct tasklet_struct dma_op_complete_tsk;
    volatile vsd_hw_regs_t *hwregs;

    vsd_task_t tasks_queue[VSD_DEV_CMD_QUEUE_MAX_LEN];
    int queue_l;
    int queue_r;
    int last_done; // last index which was executed
    int last_result;
    spinlock_t tasks_lock; // this lock is only to access tasks_queue

    struct wait_queue_head_t wait_tasks_queue_has_slot; // we need this only in add_task_block
    
    struct wait_queue_head_t wait_dev_response_queue;
    struct mutex lock; // this lock is for blocking operations when they want to access response_queue
} vsd_dev_t;
static vsd_dev_t *vsd_dev;

#define REWRITE_REGS(_cmd, _tasklet_vaddr, _dma_paddr, _dma_size, _dev_offset) \
    vsd_dev->hwregs->tasklet_vaddr = (uint64_t)(_tasklet_vaddr); \
    vsd_dev->hwregs->dma_paddr = (uint64_t)(_dma_paddr); \
    vsd_dev->hwregs->dma_size = (uint64_t)(_dma_size); \
    vsd_dev->hwregs->dev_offset = (uint64_t)(_dev_offset); \
    wmb(); \
    vsd_dev->hwregs->cmd = (uint8_t)(_cmd);

#define LOCAL_DEBUG 0
static void print_vsd_dev_hw_regs(vsd_dev_t *vsd_dev)
{
    if (!LOCAL_DEBUG)
        return;

    pr_notice(LOG_TAG "VSD dev hwregs: \n"
            "CMD: %x \n"
            "RESULT: %x \n"
            "TASKLET_VADDR: %llx \n"
            "dma_paddr: %llx \n"
            "dma_size:  %llx \n"
            "dev_offset: %llx \n"
            "dev_size: %llx \n",
            vsd_dev->hwregs->cmd,
            vsd_dev->hwregs->result,
            vsd_dev->hwregs->tasklet_vaddr,
            vsd_dev->hwregs->dma_paddr,
            vsd_dev->hwregs->dma_size,
            vsd_dev->hwregs->dev_offset,
            vsd_dev->hwregs->dev_size
    );
}

static int vsd_dev_open(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev opened\n");
    return 0;
}

static int vsd_dev_release(struct inode *inode, struct file *filp)
{
    pr_notice(LOG_TAG "vsd dev closed\n");
    return 0;
}

// ========================= TASKLET ===========================

static int get_queue_size();

static void take_next_task()
{
    vsd_hw_regs_t *reg;

    if (get_queue_size() > 0) {
        spin_lock(&vsd_dev->tasks_lock);
        reg = &vsd_dev->tasks_queue[vsd_dev->queue_l];
        vsd_dev->hwregs->cmd = reg->cmd;
        vsd_dev->hwregs->tasklet_vaddr = reg->tasklet_vaddr;
        vsd_dev->hwregs->dma_paddr = reg->dma_paddr;
        vsd_dev->hwregs->dma_size = reg->dma_size;
        vsd_dev->hwregs->dev_offset = reg->dev_offset;
        vsd_dev->last_done = (vsd_dev->queue_l - 1 + VSD_DEV_CMD_QUEUE_MAX_LEN) % VSD_DEV_CMD_QUEUE_MAX_LEN;
        vsd_dev->queue_l++;
        wmb();
        spink_unlock(&vsd_dev->tasks_lock);
    } else {
        &vsd_dev->hwregs->cmd = VSD_CMD_NONE;
    }
}

static void vsd_dev_dma_op_complete_tsk_func(unsigned long unused)
{
    (void)unused;
    take_next_task();
    wake_up(&vsd_dev->wait_dev_response_queue);
}

// ======================= TASKS QUEUE COMMON =====================

static int get_queue_size()
{
    if (vsd_dev->queue_r >= vsd_dev->queue_l)
        return vsd_dev->queue_r - vsd_dev->queue_l;
    else
        return vsd_dev->queue_r - vsd_dev->queue_l + VSD_DEV_CMD_QUEUE_MAX_LEN;
}

static int add_task_nonblock(uint8_t cmd, uint64_t tasklet_vaddr, uint64_t dma_paddr, uint64_t dma_size, uint64_t dev_offset)
{
    int index;
    vsd_hw_regs_t *reg;

    spin_lock(&vsd_dev->tasks_lock);
    if (get_queue_size == VSD_DEV_CMD_QUEUE_MAX_LEN) {
        spin_unlock(&vsd_dev->tasks_lock);
        return -EAGAIN;
    }

    reg = &vsd_dev->tasks_queue[vsd_dev->queue_r];
    reg->cmd = cmd;
    reg->tasklet_vaddr = tasklet_vaddr;
    reg->dma_paddr = dma_paddr;
    reg->dma_size = dma_size;
    reg->dev_offset = dev_offset;
    index = vsd_dev->queue_r;
    vsd_dev->queue_r++;
    wmb();
    spin_unlock(&vsd_dev->tasks_lock);

    return index;
}

static void add_task_block(uint8_t cmd, uint64_t tasklet_vaddr, uint64_t dma_paddr, uint64_t dma_size, uint64_t dev_offset)
{
    int index;
    mutex_lock(&vsd_dev->lock);
    wait_event(&vsd_dev->wait_tasks_queue_has_slot, (index = add_task_nonblock(cmd, tasklet_vaddr, dma_paddr, dma_size, dev_offset)) >= 0);
    mutex_unlock(&vsd_dev->lock);
    return index;
}

// ======================== READS ================================

static ssize_t vsd_dev_read_nonblock(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    void *tmp_buf;
    int ret;

    tmp_buf = kmalloc(read_size, GFP_ATOMIC);
    if (tmp_buf == NULL)
       return -ENOMEM;

    ret = add_task_nonblock(
            VSD_CMD_READ, 
            &vsd_dev->dma_op_complete_tsk,
            virt_to_phys(tmp_buf),
            read_size,
            *fpos,
    );

    if (ret < 0)
        return ret; // task queue is full

    /* 
     * we cant wait and we dont know when device will call tasklet
     * (he does it every second) so just finish
     *
     * IDK when should we copy to user
     */

    return 0;
}

static ssize_t vsd_dev_read_block(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    void *tmp_buf;
    int index;

    tmp_buf = kmalloc(read_size, GFP_ATOMIC);
    if (tmp_buf == NULL)
       return -ENOMEM;

    index = add_task_block(
            VSD_CMD_READ, 
            &vsd_dev->dma_op_complete_tsk,
            virt_to_phys(tmp_buf),
            read_size,
            *fpos,
    );

    mutex_lock(&vsd_dev->lock);
    wait_event(&vsd_dev->wait_dev_response_queue, index == vsd_dev->last_done);
    mutex_unlock(&vsd_dev->lock);

    if (copy_to_user(read_user_buf, tmp_buf, vsd_dev->hwregs->result)) {
        kfree(tmp_buf);
        return -EFAULT;
    }

    kfree(tmp_buf);
    return vsd_dev->last_result;
}

static ssize_t vsd_dev_read(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    if (filp->f_flags & O_NONBLOCK)
        return vsd_dev_read_nonblock(filp, read_user_buf, read_size, fpos);
    else
        return vsd_dev_read_block(filp, read_user_buf, read_size, fpos);
}

// ============================ WRITES =============================

static ssize_t vsd_dev_write_nonblock(struct file *filp,
    char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    void *tmp_buf;
    int ret;

    tmp_buf = kmalloc(write_size, GFP_ATOMIC);
    if (tmp_buf == NULL)
       return -ENOMEM;

    ret = add_task_nonblock(
            VSD_CMD_WRITE, 
            &vsd_dev->dma_op_complete_tsk,
            virt_to_phys(tmp_buf),
            write_size,
            *fpos,
    );

    if (ret < 0)
        return ret; // task queue is full

    /* 
     * we cant wait and we dont know when device will call tasklet
     * (he does it every second) so just finish
     */

    return 0;
}

static ssize_t vsd_dev_write_block(struct file *filp,
    char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    void *tmp_buf;
    int index;

    tmp_buf = kmalloc(read_size, GFP_ATOMIC);
    if (tmp_buf == NULL)
       return -ENOMEM;

    if (copy_from_user(read_user_buf, tmp_buf, write_size)) {
        kfree(tmp_buf);
        return -EFAULT;
    }

    index = add_task_block(
            VSD_CMD_WRITE, 
            &vsd_dev->dma_op_complete_tsk,
            virt_to_phys(tmp_buf),
            write_size,
            *fpos,
    );

    mutex_lock(&vsd_dev->lock);
    wait_event(&vsd_dev->wait_dev_response_queue, vsd_dev->last_done );
    mutex_unlock(&vsd_dev->lock);

    kfree(tmp_buf);
    return vsd_dev->hwregs->result;
}

static ssize_t vsd_dev_write(struct file *filp,
    char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    if (filp->f_flags & O_NONBLOCK)
        return vsd_dev_write_nonblock(filp, write_user_buf, write_size, fpos);
    else
        return vsd_dev_write_block(filp, write_user_buf, write_size, fpos);
}

// =========================================================================

static loff_t vsd_dev_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t newpos = 0;

    switch(whence) {
        case SEEK_SET:
            newpos = off;
            break;
        case SEEK_CUR:
            newpos = filp->f_pos + off;
            break;
        case SEEK_END:
            newpos = vsd_dev->hwregs->dev_size - off;
            break;
        default: /* can't happen */
            return -EINVAL;
    }
    if (newpos < 0) return -EINVAL;
    if (newpos >= vsd_dev->hwregs->dev_size)
        newpos = vsd_dev->hwregs->dev_size;

    filp->f_pos = newpos;
    return newpos;
}

static long vsd_ioctl_get_size(vsd_ioctl_get_size_arg_t __user *uarg)
{
    vsd_ioctl_get_size_arg_t arg;
    if (copy_from_user(&arg, uarg, sizeof(arg)))
        return -EFAULT;

    arg.size = vsd_dev->hwregs->dev_size;

    if (copy_to_user(uarg, &arg, sizeof(arg)))
        return -EFAULT;
    return 0;
}

static long vsd_ioctl_set_size(vsd_ioctl_set_size_arg_t __user *uarg)
{
    (void)uarg;
    // TODO
    return -EINVAL;
}

static long vsd_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
    switch(cmd) {
        case VSD_IOCTL_GET_SIZE:
            return vsd_ioctl_get_size((vsd_ioctl_get_size_arg_t __user*)arg);
            break;
        case VSD_IOCTL_SET_SIZE:
            return vsd_ioctl_set_size((vsd_ioctl_set_size_arg_t __user*)arg);
            break;
        default:
            return -ENOTTY;
    }
}

static struct file_operations vsd_dev_fops = {
    .owner = THIS_MODULE,
    .open = vsd_dev_open,
    .release = vsd_dev_release,
    .read = vsd_dev_read,
    .write = vsd_dev_write,
    .llseek = vsd_dev_llseek,
    .unlocked_ioctl = vsd_dev_ioctl
};

#undef LOG_TAG
#define LOG_TAG "[VSD_DRIVER] "

static int vsd_driver_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct resource *vsd_control_regs_res = NULL;
    pr_notice(LOG_TAG "probing for device %s\n", pdev->name);

    vsd_dev = (vsd_dev_t*)
        kzalloc(sizeof(*vsd_dev), GFP_KERNEL);
    if (!vsd_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    tasklet_init(&vsd_dev->dma_op_complete_tsk,
            vsd_dev_dma_op_complete_tsk_func, 0);
    vsd_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    vsd_dev->mdev.name = "vsd";
    vsd_dev->mdev.fops = &vsd_dev_fops;
    vsd_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;

    if ((ret = misc_register(&vsd_dev->mdev)))
        goto error_misc_reg;

    vsd_control_regs_res = platform_get_resource_byname(
            pdev, IORESOURCE_REG, "control_regs");
    if (!vsd_control_regs_res) {
        ret = -ENOMEM;
        goto error_get_res;
    }
    vsd_dev->hwregs = (volatile vsd_hw_regs_t*)
        phys_to_virt(vsd_control_regs_res->start);
    
    init_waitqueue_head(&vsd_dev->wait_tasks_queue_has_slot);
    init_waitqueue_head(&vsd_dev->wait_dev_response_queue);
    INIT_LIST_HEAD(&vsd_dev->task_queue);
    spin_lock_init(&vsd_dev->tasks_lock);
    mutex_init(&vsd_dev->lock);
    vsd_dev->queue_l = 0;
    vsd_dev->queue_r = 0;

    print_vsd_dev_hw_regs(vsd_dev);
    pr_notice(LOG_TAG "VSD dev with MINOR %u"
        " has started successfully\n", vsd_dev->mdev.minor);
    return 0;

error_get_res:
    misc_deregister(&vsd_dev->mdev);
error_misc_reg:
    kfree(vsd_dev);
    vsd_dev = NULL;
error_alloc:
    return ret;
}

static int vsd_driver_remove(struct platform_device *dev)
{
    // module can't be unloaded if its users has even single
    // opened fd
    pr_notice(LOG_TAG "removing device %s\n", dev->name);
    misc_deregister(&vsd_dev->mdev);
    kfree(vsd_dev);
    vsd_dev = NULL;
    return 0;
}

static struct platform_driver vsd_driver = {
    .probe = vsd_driver_probe,
    .remove = vsd_driver_remove,
    .driver = {
        .name = "au-vsd",
        .owner = THIS_MODULE,
    }
};

static int __init vsd_driver_init(void)
{
    return platform_driver_register(&vsd_driver);
}

static void __exit vsd_driver_exit(void)
{
    // This indirectly calls vsd_driver_remove
    platform_driver_unregister(&vsd_driver);
}

module_init(vsd_driver_init);
module_exit(vsd_driver_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU Virtual Storage Device driver module");
MODULE_AUTHOR("Kernel hacker!");
