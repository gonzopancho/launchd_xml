/* (C) 2014 by Optim Inc., Scott V. Kamp 
   outbackdingo@gmail.com 
 */


/* (C) 2007 by InfoWeapons Inc., Paul Buetow
   pbuetow@infoweapons.com
   launchd@dev.buetow.org
 */ 

#ifndef LAUNCH_XML_H
#define LAUNCH_XML_H

#include <bsdxml.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define XMLFILE "/etc/pfsense.xml"

#ifndef INDENT_OFFSET
#define INDENT_OFFSET 5
#endif

#define XMLDOMBUFSIZE 4068

typedef struct STACKELEM_ {
    struct STACKELEM_ *next;
    void *value;
} STACKELEM;

typedef struct STACK_ {
    struct STACKELEM_ *top;
} STACK;

typedef struct LISTELEM_ {
    void *value;
    struct LISTELEM_ *next;
    struct LISTELEM_ *prev;
} LISTELEM;

typedef struct {
    LISTELEM *first;
    LISTELEM *last;
} LIST;

typedef enum {
    Leaf,
    NotLeaf
} DOMELEMTYPE;

typedef struct DOMELEM_ {
    char *name;
    LIST *list;
    DOMELEMTYPE type;
} DOMELEM;

typedef struct {
    DOMELEM *root;
} DOM;

typedef struct {
    STACK *stack;
    DOM *dom;
} PARSEDATA;

char* strchrl(char *str, char c);
void memerror();
void usage(char *appname);
void* ccalloc(size_t number, size_t size);
void* mmalloc(size_t size);

STACK *stack_copy_reverse(STACK *s);
STACK* stack_new();
STACKELEM* stackelem_new(void *v);
int stack_islastelem(STACK *s);
int stack_empty(STACK *s);
int stack_top_strcmp(STACK *s, char *c);
void stack_free();
void stack_print_str(STACK *s);
void stack_push(STACK *s, void *v);
void stack_push_strcpy(STACK *s, char *c);
void stackelem_free(STACKELEM *e);
void* stack_pop(STACK *s);
void* stack_top(STACK *s);

PARSEDATA* parsedata_new();
void parsedata_free(PARSEDATA* pd);

LIST* list_new();
LISTELEM* list_get_elem_cb(LIST *l, void *v, int (*cmp)(void*, void*) );
LISTELEM* listelem_new(void *v);
void list_add_back(LIST *l, void *v);
void list_free(LIST *l);
void list_iterate_cb(LIST *l, void (*iter)(void*));
void list_iterate_cb2(LIST *l, void *v, void (*iter)(void*, void*));
void list_iterate_cb3(LIST *l, void *v1, void *v2, void (*iter)(void*, void*, void*));
void list_print_indented_str(LIST *l, unsigned indent);
void list_print_str(LIST *l);
void* list_first(LIST *l);
void* list_remove_front(LIST *l);

DOMELEM* domelem_new(char *name);
void domelem_free(DOMELEM *e);
void domelem_print(DOMELEM *e);
void domelem_print_indented(DOMELEM *e, unsigned indent);
void domelem_keys(DOMELEM *e, STACK *s);

DOM* dom_new();
char* dom_get(DOM *dom, char *name);
int dom_num(DOM *dom, char *name);
LIST* dom_list(DOM *dom, char *name);
int dom_add(DOM *dom, STACK *s, char *value);
void dom_free(DOM *dom);
void dom_print(DOM *dom);
void dom_keys(DOM *dom);
void dom_set_root(DOM *dom, DOMELEM *e);

#endif
