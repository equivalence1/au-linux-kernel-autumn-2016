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
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/semaphore.h>

#include "../vsd_device/vsd_hw.h"
#include "vsd_ioctl.h"

#define LOG_TAG "[VSD_CHAR_DEVICE] "

typedef struct vsd_dev {
    struct miscdevice mdev;
    struct tasklet_struct dma_op_complete_tsk;
    volatile vsd_hw_regs_t *hwregs;
} vsd_dev_t;
static vsd_dev_t *vsd_dev;
    
static struct semaphore sem;
static wait_queue_head_t pending_q; // this will always contain only <= 1 elements

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

static void vsd_dev_dma_op_complete_tsk_func(unsigned long unused)
{
    (void)unused;
    vsd_dev->hwregs->cmd = VSD_CMD_NONE;
    mb();
    wake_up(&pending_q);
}

#define UNLOCK_AND_FREE(buff_to_free) \
    up(&sem); \
    kfree(buff_to_free);

#define REWRITE_REGS(_cmd, _tasklet_vaddr, _dma_paddr, _dma_size, _dev_offset) \
    vsd_dev->hwregs->tasklet_vaddr = (uint64_t)(_tasklet_vaddr); \
    vsd_dev->hwregs->dma_paddr = (uint64_t)(_dma_paddr); \
    vsd_dev->hwregs->dma_size = (uint64_t)(_dma_size); \
    vsd_dev->hwregs->dev_offset = (uint64_t)(_dev_offset); \
    wmb(); \
    vsd_dev->hwregs->cmd = (uint8_t)(_cmd);

static ssize_t vsd_dev_read(struct file *filp,
    char __user *read_user_buf, size_t read_size, loff_t *fpos)
{
    void *tmp_buf;
    if (down_interruptible(&sem))
        return -ERESTARTSYS;

    tmp_buf = kmalloc(read_size, GFP_KERNEL);
    if (tmp_buf == NULL) {
        UNLOCK_AND_FREE(tmp_buf);
        return -ENOMEM;
    }

    REWRITE_REGS(
            VSD_CMD_READ,
            &vsd_dev->dma_op_complete_tsk,
            virt_to_phys(tmp_buf),
            read_size,
            *fpos
    )

    wait_event(pending_q, vsd_dev->hwregs->cmd == VSD_CMD_NONE);

    if (copy_to_user(read_user_buf, tmp_buf, vsd_dev->hwregs->result)) {
        UNLOCK_AND_FREE(tmp_buf);
        return -EFAULT;
    }

    UNLOCK_AND_FREE(tmp_buf);
    return vsd_dev->hwregs->result;
}

static ssize_t vsd_dev_write(struct file *filp,
    const char __user *write_user_buf, size_t write_size, loff_t *fpos)
{
    void *tmp_buf;
    if (down_interruptible(&sem))
        return -ERESTARTSYS;

    tmp_buf = kmalloc(write_size, GFP_KERNEL);
    if (tmp_buf == NULL) {
        UNLOCK_AND_FREE(tmp_buf);
        return -ENOMEM;
    }

    if (copy_from_user(tmp_buf, write_user_buf, write_size)) {
        UNLOCK_AND_FREE(tmp_buf);
        return -EFAULT;
    }

    REWRITE_REGS(
            VSD_CMD_WRITE,
            &vsd_dev->dma_op_complete_tsk,
            virt_to_phys(tmp_buf),
            write_size,
            *fpos
    )

    wait_event(pending_q, vsd_dev->hwregs->cmd == VSD_CMD_NONE);

    UNLOCK_AND_FREE(tmp_buf);
    return vsd_dev->hwregs->result;
}

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
    vsd_ioctl_get_size_arg_t *tmp_arg;
    if (down_interruptible(&sem))
        return -ERESTARTSYS;

    tmp_arg = (vsd_ioctl_get_size_arg_t *)kmalloc(sizeof(*tmp_arg), GFP_KERNEL);
    if (tmp_arg == NULL) {
        UNLOCK_AND_FREE(tmp_arg);
        return -ENOMEM;
    }

    if (copy_from_user(tmp_arg, uarg, sizeof(vsd_ioctl_get_size_arg_t))) {
        UNLOCK_AND_FREE(tmp_arg);
        return -EFAULT;
    }

    REWRITE_REGS(
            VSD_CMD_SET_SIZE,
            &vsd_dev->dma_op_complete_tsk,
            0,
            0,
            tmp_arg->size
    )

    wait_event(pending_q, vsd_dev->hwregs->cmd == VSD_CMD_NONE);

    UNLOCK_AND_FREE(tmp_arg);
    return vsd_dev->hwregs->result;
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
        | S_IWUSR | S_IWGRP | S_IWOTH;

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
    init_waitqueue_head(&pending_q);
    sema_init(&sem, 1);

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
