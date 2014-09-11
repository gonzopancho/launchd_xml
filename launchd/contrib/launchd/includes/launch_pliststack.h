#ifndef _PLISTSTACK_H
#define _PLISTSTACK_H

#include "launch.h"

typedef struct plist_node *PLISTNODE;
typedef PLISTNODE STACK;

int is_empty(STACK stack);
STACK create_stack(void);
void dispose_stack(STACK stack);
void make_empty(STACK stack);
void push(launch_data_t element, STACK stack);
launch_data_t top(STACK stack);
void pop(STACK stack);

#endif /* _PLIST_STACK_H */
