#ifndef _GLOBAL_
#define _GLOBAL_

#include "../libft/libft.h"

typedef struct          s_container
{
    char                *hash_alg;
    uint8_t             flags;
    t_list              *message;
}                       t_container;

#endif