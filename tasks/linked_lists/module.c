#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>

#include "stack.h"
#include "assert.h"

static int __init test_stack(void)
{
    int ret = 0;
    LIST_HEAD(data_stack);
    stack_entry_t *tos = NULL;
    const char *tos_data = NULL;
    const char* test_data[] = { "1", "2", "3", "4" };
    long i = 0;

    pr_alert("Testing basic stack");

    for (i = 0; i != ARRAY_SIZE(test_data); ++i) {
        tos = create_stack_entry((void*)test_data[i]);
        if (!tos) {
            ret = -ENOMEM;
            break;
        }
        stack_push(&data_stack, tos);
    }

    for (i = ARRAY_SIZE(test_data) - 1; i >= 0; --i) {
        tos = stack_pop(&data_stack);
        tos_data = STACK_ENTRY_DATA(tos, const char*);
        delete_stack_entry(tos);
        printk(KERN_ALERT "%s == %s\n", tos_data, test_data[i]);
        assert(!strcmp(tos_data, test_data[i]));
    }

    assert(stack_empty(&data_stack));
    if (ret == 0)
        pr_alert("Test success!\n");

    return ret;
}

static int __init print_processes_backwards(void)
{
    int ret = 0;
    void *process_name = NULL;
    stack_entry_t *tos = NULL;
    struct task_struct *p;
    LIST_HEAD(process_stack);

    for_each_process(p) {
        process_name = kmalloc(TASK_COMM_LEN, GFP_KERNEL);
        if (process_name == NULL) {
            ret = -ENOMEM;
            break;
        }
        get_task_comm((char *)process_name, p);
        tos = create_stack_entry(process_name);
        if (tos == NULL) {
            kfree(process_name);
            ret = -ENOMEM;
            break;
        }
        stack_push(&process_stack, tos);
    }

    while (!list_empty(&process_stack)) {
        tos = stack_pop(&process_stack);
        process_name = STACK_ENTRY_DATA(tos, char *);
        delete_stack_entry(tos);
        if (ret == 0) // i do know if i should print processes even if we failed at some point
            printk(KERN_ALERT "%s\n", (char *)process_name);
        kfree(process_name);
    }

    return ret;
}

static int __init ll_init(void)
{
    int ret = 0;
    printk(KERN_ALERT "Hello, linked_lists\n");

    ret = test_stack();
    if (ret)
        goto error;

    ret = print_processes_backwards();

error:
    return ret;
}

static void __exit ll_exit(void)
{
    printk(KERN_ALERT "Goodbye, linked_lists!\n");
}

module_init(ll_init);
module_exit(ll_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Linked list exercise module");
MODULE_AUTHOR("Kernel hacker!");
