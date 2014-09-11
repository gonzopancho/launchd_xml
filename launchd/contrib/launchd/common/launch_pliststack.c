/*
 * Copyright 2006 Infoweapons Corporation
 */

/** 
 * Stack implementation used by launchd parser of plist files.
 *
 *    Copyright 2006 
 *  Infoweapons Corporation.
 *
 *  @jmp@
 */

#include <stdio.h>
#include <stdlib.h>

#include "launch_pliststack.h"

struct plist_node {
	launch_data_t element;
	struct plist_node *next;
};

/*
 * Checks if stack is empty.
 * @return  0  Not empty
 *          1  If empty
 */
int is_empty(STACK stack)
{
	return (stack->next == NULL);
}

/*
 * Creates a new stack.
 */
STACK create_stack(void)
{
	STACK stack = malloc(sizeof(struct plist_node));
	if (stack == NULL) {
		fprintf(stderr, "Unable to allocate memory!");
		exit(1);
	}
	stack->next = NULL;
	return (stack);
}

/*
 * Cleanup function for deallocation of stack.
 */
void dispose_stack(STACK stack)
{
	make_empty(stack);
	free(stack);
}

/*
 * Clears stack.
 */
void make_empty(STACK stack)
{
	if (stack == NULL)
		fprintf(stderr, "Stack not created");
	else
		while (!is_empty(stack))
			pop(stack);
}

/*
 * Insert new element in stack.
 */
void push(launch_data_t element, STACK stack)
{
	PLISTNODE tmpnode = malloc(sizeof(struct plist_node));
	if (tmpnode == NULL) {
		fprintf(stderr, "Unable to allocate memory!");
		exit(1);
	}
	tmpnode->element = element;
	tmpnode->next = stack->next;
	stack->next = tmpnode;
}

/*
 * Gets top element of stack.
 */
launch_data_t top(STACK stack)
{
	if (!is_empty(stack))
		return (stack->next->element);
        /* for empty stack, return NULL */
	return (NULL);
}

/*
 * Removes top element of stack.
 */
void pop(STACK stack)
{
	PLISTNODE firstnode;

	if (is_empty(stack))
		fprintf(stderr, "Stack empty!");
	else {
		firstnode = stack->next;
		stack->next = stack->next->next;
		free(firstnode);
	}
}
