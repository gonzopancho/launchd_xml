/* (C) 2014 by Optim Inc., Scott V. Kamp
   outbackdingo@gmail.com
 */

/* (C) 2007 by InfoWeapons Inc., Paul Buetow
   pbuetow@infoweapons.com
   launchd@dev.buetow.org
 */ 

#include "launch_xml.h"

void _indent(unsigned spaces);
STACK* _tokenize_name(char *name);

// Find last occurance of c in str and return pointer to
// one position afterwards
char* strchrl(char *str, char c) {
    char *walk1 = str, *walk2;

    while ( (walk2 = strchr(walk1, c)) )
        walk1 = walk2 + 1;

    return walk1;
}

void memerror() {
    fprintf(stderr, "Out of memory\n");
    exit(1);
}

void* ccalloc(size_t number, size_t size) {
    void *p = calloc(number, size);

    if (!p) memerror();

    return p;
}

void* mmalloc(size_t size) {
    void *p = malloc(size);

    if (!p) memerror();

    return p;
}

STACK* _tokenize_name(char *name) {
    STACK *s, *sreversed;
    char *pos, *part;
    int len;

    if (!name)
        return NULL;

    // ".foo.bar.baz" and "foo.bar.baz." are illegal
    if (name[0] == '.' || name[strlen(name)-1] == '.')
        return NULL;

    s = stack_new();

    while ((pos = strchr(name, '.')) != NULL) {
        len = pos - name;

        part = ccalloc(len+1, sizeof(char));
        strncpy(part, name, len);
        part[len] = 0;
        stack_push(s, part);

        name = pos + 1;
    }

    len = strlen(name);
    part = ccalloc(len+1, sizeof(char));
    strncpy(part, name, len);
    part[len] = 0;
    stack_push(s, name);

    sreversed = stack_copy_reverse(s);
    stack_free(s);

    return sreversed;
}

void _indent(unsigned spaces) {
    unsigned i;

    for (i = 0; i < spaces; ++i)
        printf(" ");
}

int _cmp_cb(void *v1, void *v2) {
    char *c1, *c2;
    DOMELEM *e;

    if (!v1 || !v2)
        return -1;

    e = v2;

    if (!e->name)
        return -1;

    c1 = v1; c2 = e->name;

    return strncmp(c1, c2, strlen(c1));
}

STACKELEM* stackelem_new(void *v) {
    STACKELEM *e = mmalloc(sizeof(STACKELEM));

    e->value = v;
    e->next = NULL;

    return e;
}

void stackelem_free(STACKELEM *e) {
    if (!e)
        return;

    free(e);
}

STACK* stack_new() {
    STACK *s = mmalloc(sizeof(STACK));

    s->top = NULL;
    return s;
}

void stack_free(STACK *s) {
    STACKELEM *e, *p; // Element & prev element

    if (!s)
        return;

    e = s->top;

    while (e != NULL) {
        p = e;
        e = e->next;
        stackelem_free(p);
    }

    free(s);
}

void* stack_pop(STACK *s) {
    void *v;
    STACKELEM *e;

    if (!s || !s->top)
        return NULL;

    e = s->top;
    s->top = e->next;
    v = e->value;
    stackelem_free(e);

    return v;
}

int stack_islastelem(STACK *s) {
    if (!s || !s->top)
        return 0;

    if (!s->top->next)
        return 1;

    return 0;
}
int stack_empty(STACK *s) {
    if (!s || !s->top)
        return 1;

    return 0;
}

void* stack_top(STACK *s) {
    if (!s || !s->top)
        return NULL;

    return s->top->value;
}

int stack_top_strcmp(STACK *s, char *c) {
    if (!s || !s->top || !s->top->value)
        return -1;

    else if (!c)
        return 1;

    return strncmp((char*) s->top->value, c, strlen(c));
}

void stack_push(STACK *s, void *v) {
    STACKELEM *e;

    if (!s)
        return;

    e = stackelem_new(v);
    e->next = s->top;
    s->top = e;
}

void stack_push_strcpy(STACK *s, char *c) {
    int len;
    char *copy;

    if (!s || !c)
        return;

    len = strlen(c);
    copy = ccalloc(len+1, sizeof(char));

    strncpy(copy, c, len);
    copy[len] = 0;

    stack_push(s, copy);
}

void stack_print_str(STACK *s) {
    STACKELEM *e;

    printf("Stack:\n");

    if (!s || !s->top) {
        unsigned i;
        for (i = 0; i < INDENT_OFFSET; ++i)
            printf(" ");

        printf("EMPTY\n");
        return;
    }

    e = s->top;

    while (e) { // != NULL
        unsigned i;
        for (i = 0; i < INDENT_OFFSET; ++i)
            printf(" ");

        printf("%s\n", e->value != NULL ? (char*) e->value : "(null)");

        e = e->next;
    }

}

STACK *stack_copy_reverse(STACK *s) {
    if (!s)
        return NULL;

    STACK *scopy = stack_new();
    STACKELEM *e = s->top, *ecopy = NULL, *eprev = NULL;

    while (e) {
        void *v = e->value;
        ecopy = stackelem_new(v);

        if (eprev)
            ecopy->next = eprev;

        eprev = ecopy;
        e = e->next;
    }

    scopy->top = ecopy;

    return scopy;
}

LISTELEM* listelem_new(void *v) {
    LISTELEM *e = mmalloc(sizeof(LISTELEM));

    e->value = v;
    e->prev = NULL;
    e->next = NULL;

    return e;
}

LIST* list_new() {
    LIST *l = mmalloc(sizeof(LIST));
    l->first = l->last = NULL;

    return l;
}

void list_free(LIST *l) {
    if (!l)
        return;

    if (l->first) {
        LISTELEM *e = l->first;

        while (e) {
            LISTELEM *next;

            next = e->next;
            free(e);
            e = next;
        }
    }

    free(l);
}

void list_add_back(LIST *l, void *v) {
    if (!l || !v)
        return;

    LISTELEM *e = listelem_new(v);

    if (!l->first) {
        l->first = l->last = e;
        e->next = e->prev = NULL;

    } else {
        l->last->next = e;
        e->prev = l->last;
        l->last = e;
    }
}

void* list_remove_front(LIST *l) {
    if (!l || !l->first)
        return NULL;

    LISTELEM *e = l->first;;
    void *v = e->value;

    l->first = e->next;

    if (l->first)
        l->first->prev = NULL;

    free(e);

    return v;
}

void list_print_indented_str(LIST *l, unsigned indent) {
    if (!l)
        return;

    LISTELEM *e = l->first;

    _indent(indent);
    printf("list: ");

    while (e) {
        _indent(indent);
        printf("%s ", (char*)e->value);
        e = e->next;
    }

    printf("\n");
}

void list_print_str(LIST *l) {
    list_print_indented_str(l, 0);
}

LISTELEM* list_get_elem_cb(LIST *l, void *v, int (cmp)(void*, void*) ) {
    LISTELEM *e;

    if (!l)
        return NULL;

    e = l->first;

    while (e) {
        if ( 0 == (*cmp) (v, e->value) )
            return e;

        e = e->next;
    }

    return NULL;
}

int _domelem_list_exists_str(LIST *l, char *str) {
    LISTELEM *le;

    if (!l)
        return 0;

    le = l->first;

    while (le) {
        DOMELEM *de = le->value;
        char *val = de->name;

        if (strncmp(val, str, strlen(str)) == 0)
            return 1;

        le = le->next;
    }

    return 0;
}

void list_iterate_cb(LIST *l, void (*iter)(void*)) {
    LISTELEM *le;

    if (!l)
        return;

    le = l->first;

    while (le) {
        (*iter) (le);
        le = le->next;
    }
}

void list_iterate_cb2(LIST *l, void *v, void (*iter)(void*, void*)) {
    LISTELEM *le;

    if (!l)
        return;

    le = l->first;

    while (le) {
        (*iter) (v, le);
        le = le->next;
    }
}

void list_iterate_cb3(LIST *l, void *v1, void *v2,
                      void (*iter)(void*, void*, void*)) {

    LISTELEM *le;

    if (!l)
        return;

    le = l->first;

    while (le) {
        (*iter) (v1, v2, le);
        le = le->next;
    }
}

void* list_first(LIST *l) {
    if (!l || !l->first)
        return NULL;

    return l->first->value;
}

DOMELEM* domelem_new(char *name) {
    DOMELEM *e;

    if (!name)
        return NULL;

    e = mmalloc(sizeof(DOMELEM));

    int len = strlen(name);
    e->name = ccalloc(len+1, sizeof(char));
    strncpy(e->name, name, len);
    e->name[len] = 0;

    e->list = list_new();
    e->type = NotLeaf;

    return e;
}

void _domelem_free(void *v) {
    LISTELEM *le = v;

    if (!le || !le->value)
        return;

    domelem_free( (DOMELEM*) le->value );
}

void domelem_free(DOMELEM *e) {
    if (!e)
        return;

    if (e->name)
        free(e->name);

    if (e->list) {
        list_iterate_cb(e->list, _domelem_free);
        list_free(e->list);
    }

    free(e);
}

void _domelem_print_cb(void *v1, void *v2) {
    int indent = * (int*) v1;
    LISTELEM *le = v2;
    DOMELEM *e = le->value;

    domelem_print_indented(e, indent + INDENT_OFFSET);
}

void _domelem_keys_cb(void *v1, void *v2) {
    STACK *s = v1;
    LISTELEM *le = v2;
    DOMELEM *e = le->value;

    domelem_keys(e, s);
}

void domelem_print_indented(DOMELEM *e, unsigned indent) {
    if (e->name) {
        _indent(indent);

        if (e->type == Leaf) {
            printf("\"%s\"\n", e->name);
        } else {
            printf("(%s)\n", e->name);
        }
    }
    if (e->list) {
        list_iterate_cb2(e->list, &indent, _domelem_print_cb);
    }
}

void domelem_print(DOMELEM *e) {
    printf("XML tree:\n");
    domelem_print_indented(e, INDENT_OFFSET);
}

void domelem_keys(DOMELEM *e, STACK *s) {
    int flag = 0;

    if (e->name) {
        if (e->type == Leaf) {
            STACK *rs = stack_copy_reverse(s);

            while (!stack_empty(rs)) {
                char *part = stack_pop(rs);

                if (stack_empty(rs))
                    printf("%s\n", part);
                else
                    printf("%s.", part);
            }

            stack_free(rs);

        } else {
            stack_push(s, e->name);
            flag = 1;
        }
    }

    if (e->list)
        list_iterate_cb2(e->list, s, _domelem_keys_cb);

    if (flag)
        stack_pop(s);
}


DOM* dom_new() {
    DOM *dom = mmalloc(sizeof(DOM));
    dom->root = NULL;

    return dom;
}

void dom_free(DOM *dom) {
    if (!dom)
        return;

    if (dom->root)
        domelem_free(dom->root);

    free(dom);
}

void dom_set_root(DOM *dom, DOMELEM *e) {
    if (dom && e)
        dom->root = e;
}

int dom_add(DOM *dom, STACK *s, char *value) {
    LISTELEM *le;
    DOMELEM *e, *leaf;
    char *c;

    if (!dom || !s)
        return -1;

    e = dom->root;

    // Set the root node if not yet existend
    if (!e) {
        c = stack_pop(s);
        dom->root = e = domelem_new(c);
    }

    if (strncmp(e->name, stack_top(s), strlen(e->name)) == 0)
        stack_pop(s);

    while (e) {
        c = stack_pop(s);

        // We found the element
        if (!c) {
            break;
        }

        // Look if in the child list if the element exists
        le = list_get_elem_cb(e->list, c, _cmp_cb);

        // Yes does exist
        if (le) {
            // Check if its the last element in the stack
            if (stack_empty(s)) {
                // Check if the key already exists!
                if (_domelem_list_exists_str(e->list, c)) {
                    int index = 1, len;
                    char temp[1024];

                    do {
                        sprintf(temp, "%s-%d", c, ++index);
                    } while ( _domelem_list_exists_str(e->list, temp) );
                    len = strlen(temp);
                    c = realloc(c, sizeof(char)*(len+1));
                    strncpy(c, temp, len);
                    c[len] = 0;

                    DOMELEM *e_ = domelem_new(c);
                    list_add_back(e->list, e_);
                    e = e_;
                    continue;

                }
            }

            // Go one level deeper
            e = le->value;
            continue;

        } else {
            // Does not exist, create new domelem and go one level deeper
            DOMELEM *e_ = domelem_new(c);
            list_add_back(e->list, e_);
            e = e_;
        }
    }

    leaf = domelem_new(value);
    leaf->type = Leaf;
    list_add_back(e->list, leaf);

    return 0;
}

LIST* _dom_list_prev(DOM *dom, char *name, int prev) {
    LISTELEM *le;
    DOMELEM *e = NULL, *e_prev = NULL;
    STACK *s;
    char *c = NULL;

    if (!dom || !name)
        return NULL;

    s = _tokenize_name(name);

    if (!s) {
        stack_free(s);
        return NULL;
    }

    e = dom->root;

    if (!e) {
        stack_free(s);
        return NULL;
    }

    if (strncmp(e->name, stack_top(s), strlen(e->name)) == 0)
        stack_pop(s);

    while (e) {
        c = stack_pop(s);

        // We found the element
        if (!c)
            break;

        // Look if in the child list if the element exists
        le = list_get_elem_cb(e->list, c, _cmp_cb);

        if (le) {
            // Yes does exist, go one level deeper
            e_prev = e;
            e = le->value;
            continue;

        } else {
            // Does not exist
            stack_free(s);
            return NULL;
        }
    }

    if (prev)
        return e_prev->list;

    return e->list;
}

LIST* dom_list(DOM *dom, char *name) {
    return _dom_list_prev(dom, name, 0);
}

void _list_print_names(void *v) {
    LISTELEM *le = v;
    DOMELEM *de;

    if (!le)
        return;

    de = le->value;

    printf("%s\n", de->name);
}

char* dom_get(DOM *dom, char *name) {
    DOMELEM *leaf;
    LIST* l = dom_list(dom, name);

    if (!l)
        return NULL;

    leaf = list_first(l);

    if (leaf->type == Leaf)
        return leaf->name;

    list_iterate_cb(l, _list_print_names);

    return NULL;
}

void _dom_num_cb(void *v1, void *v2, void *v3) {
    LISTELEM *le = v3;
    DOMELEM *de = le->value;
    char *str1 = v2, *str2 = de->name;
    int *num = v1;

    char *walk = strchr(str2, '-');
    int offset = walk - str2;

    if (offset < 1)
        return;

    if (strncmp(str1, str2, offset) == 0)
        ++*num;
}

int dom_num(DOM *dom, char *name) {
    LIST* l = _dom_list_prev(dom, name, 1);
    int num = 1;

    if (!l)
        return 0;

    // Create a copy of name and remove all leading levels, e.g.
    // foo.bar.baz => baz
    char *temp = strchrl(name, '.');

    list_iterate_cb3(l, &num, temp, _dom_num_cb);

    return num;
}

void dom_print(DOM *dom) {
    if (dom && dom->root)
        domelem_print(dom->root);
}

void dom_keys(DOM *dom) {
    STACK *s = stack_new();

    if (dom && dom->root)
        domelem_keys(dom->root, s);

    stack_free(s);
}

/*
 * Handler function for opening XML tag.
 */
void tag_start(void *p, const char *name, const char **atts) {
    PARSEDATA *pd = p;
    int len = strlen(name);
    char *copy = ccalloc(len+1, sizeof(char));
    strncpy(copy, name, len);
    copy[len] = 0;

    //printf("tag_start: %s\n", name);

    stack_push(pd->stack, (void*) copy);
}

/*
 * Handler function for closing XML tag.
 */
void tag_end(void *p, const char *el) {
    PARSEDATA *pd = p;

    //printf("tag_end: %s\n", el);
    // Reverse the order of the stack: foo bar baz -> baz foo bar
    //STACK *s = stack_copy_reverse(pd->stack);
    //dom_add(pd->dom, s, (char*) el);
    //stack_free(s);

    if (0 == stack_top_strcmp(pd->stack, (char*) el))
        free(stack_pop(pd->stack));
}

/*
 * Handler function for text portion.
 */
void tag_text(void *p, const XML_Char *str, int len) {
    PARSEDATA *pd = p;
    STACK *s;
    char *start, *end, *walk, *temp;

    // Ignore empty ones
    if (0 >= len)
        return;

    start = strstr(str, "<");
    end = strstr(str, "</");

    // Check if there is still some xml tag inside of this text!
    // e.g.: str = "<foo>textwewant</foo>
    if (start != end)
        return;

    // Skip whitespaces and newlines and tabs
    walk = (char*) str;
    while (/*walk[0] == '0' ||*/ walk[0] == '\n' || walk[0] == '\t')
        ++walk;

    // Recalculate the len because of the skipped stuff
    len = len - (walk - str);

    // Ignore empty ones II
    if (len == 0)
        return;

    // Reverse the order of the stack: foo bar baz -> baz foo bar
    s = stack_copy_reverse(pd->stack);

    temp = ccalloc(len+1,sizeof(char));
    strncpy(temp, walk, len);
    temp[len] = '\0';

    //printf("tag_text:(len:%d) \"%s\"\n", len, temp);

    dom_add(pd->dom, s, temp);
    free(temp);

    stack_free(s);
}

PARSEDATA* parsedata_new() {
    PARSEDATA *pd = mmalloc(sizeof(PARSEDATA));
    pd->stack = stack_new();

    return pd;
}

void parsedata_free(PARSEDATA *pd) {
    if (!pd)
        return;

    if (pd->stack)
        stack_free(pd->stack);

    free(pd);
}

DOM* xml_parse(int fd) {
    XML_Parser parser;
    PARSEDATA *pd = parsedata_new();
    DOM *dom;
    void *buff;
    int bytes_read;

    dom = pd->dom = dom_new();

    parser = XML_ParserCreate(NULL);
    XML_SetElementHandler(parser, tag_start, tag_end);
    XML_SetCharacterDataHandler(parser, tag_text);
    XML_SetUserData(parser, pd);

    for (;;) {
        buff = XML_GetBuffer(parser, XMLDOMBUFSIZE);

        if (!buff) {
            memerror();
            return NULL;
        }

        bytes_read = read(fd, buff, XMLDOMBUFSIZE);
        if (bytes_read < 0) {
            fprintf(stderr, "XML read error!");
            return NULL;
        }

        if (!XML_ParseBuffer(parser, bytes_read, bytes_read == 0)) {
            fprintf(stderr, "XML parsing error!");
            return NULL;
        }

        if (bytes_read == 0)
            break;
    }

    XML_ParserFree(parser);

    parsedata_free(pd);

    return dom;
}

DOM* config_parse(const char *file) {
    int fd;
    DOM *dom;

    if ((fd = open(file, O_RDONLY)) == 1)
        return NULL;

    /* Returns NULL if error */
    dom = xml_parse(fd);

    close(fd);

    return dom;
}

void usage(char *appname) {
    fprintf(stderr, "Usage: %s option [args]\n", appname);
    fprintf(stderr, "\tExamples:\n");
    fprintf(stderr, "\t%s -dom (prints out the whole dom xml tree)\n", appname);
    fprintf(stderr, "\t%s -get key (prints out the specific key value)\n", appname);
    fprintf(stderr, "\t%s -h  (prints out this help)\n", appname);
    fprintf(stderr, "\t%s -keys (prints out all available keys)\n", appname);
    fprintf(stderr, "\t%s -num key (prints out how often 'key' is available)\n", appname);
}

int main(int argc, char** argv) {
    DOM *dom;
    int exit = 0;
    //char *elem = "pfsense.interfaces.lan.if", *value;

    if (argc < 2) {
        fprintf(stderr, "No argument specified\n");
        usage(argv[0]);

        return 1;
    }

    dom = config_parse(XMLFILE);

    if (strncmp(argv[1], "-get", 4) == 0 || strncmp(argv[1], "-num", 4) == 0) {
        char *elem, *value = NULL;
        int num;

        if (argc < 3) {
            fprintf(stderr, "Not enough arguments specified\n");
            usage(argv[0]);

            return 1;
        }

        elem = argv[2];

        // foo.bar.baz-1 is a synonym for foo.bar.baz
        if ( strstr(elem, "-1") ) {
            int len = strlen(elem);
            elem[len-2] = 0;
            elem[len-1] = 0;
        }

        if (strncmp(argv[1], "-get", 4) == 0) {
            value = dom_get(dom, elem);

            // Empty program output if nothing found
            if (!value)
                return 1;

        } else {
            num = dom_num(dom, elem);
        }

        if (value) {
            printf("%s\n", value);

        } else {
            printf("%d\n", num);
        }

    } else if (strncmp(argv[1], "-keys", 5) == 0) {
        dom_keys(dom);

    } else if (strncmp(argv[1], "-dom", 4) == 0) {
        dom_print(dom);

    } else if (strncmp(argv[1], "-h", 2) == 0) {
        usage(argv[0]);
        exit = 0;

    } else {
        fprintf(stderr, "%s: No such option\n", argv[1]);
        usage(argv[0]);
        exit = 1;
    }

    dom_free(dom);

    return exit;
}
