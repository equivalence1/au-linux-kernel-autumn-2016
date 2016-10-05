#include "stack.h"

stack_entry_t* create_stack_entry(void *data)
{
    void *place;
    stack_entry_t *stack_entry;

    place = kmalloc(sizeof(stack_entry_t), GFP_KERNEL);
    if (place == NULL)
        return NULL;

    stack_entry = (stack_entry_t *)place;
    INIT_LIST_HEAD(&stack_entry->lh);
    stack_entry->data    = data;

    return stack_entry;
}

void delete_stack_entry(stack_entry_t *entry)
{
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
    list_add(&entry->lh, stack);
}

stack_entry_t* stack_pop(struct list_head *stack)
{
    stack_entry_t *stack_entry;

    if (list_empty(stack))
        return NULL;

    stack_entry = list_first_entry(stack, stack_entry_t, lh);
    list_del(&stack_entry->lh);

    return stack_entry;
}
