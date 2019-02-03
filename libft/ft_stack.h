#ifndef FT_STACK_H
#define FT_STACK_H
#include <stdlib.h>

typedef struct          t_StackNode {
    int                 data;
    struct t_StackNode  *next;
}                       s_StackNode;

s_StackNode     *new_node(int data);
int             stack_is_empty(s_StackNode *root);
void            stack_push(s_StackNode **root, int data);
void            stack_pop(s_StackNode **root);
int             stack_peek(s_StackNode *root);

#endif