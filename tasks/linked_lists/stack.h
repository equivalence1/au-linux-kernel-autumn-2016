#ifndef _LL_STACK_H
#define _LL_STACK_H

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/gfp.h>

typedef struct stack_entry {
    struct list_head lh;
    void *data;
} stack_entry_t;

stack_entry_t* create_stack_entry(void *data);
void delete_stack_entry(stack_entry_t *entry);

void stack_push(struct list_head *stack, stack_entry_t *entry);
stack_entry_t* stack_pop(struct list_head *stack);
#define stack_empty(stack) list_empty((stack))

#define STACK_ENTRY_DATA(stack_entry, data_ptr_type) \
    ((data_ptr_type)(stack_entry)->data)

#define STACK_ENTRY_DATA_RESET(stack_entry, new_data) \
    do { \
        (stack_entry)->data = new_data; \
    } while(0)

#endif //_LL_STACK_H
