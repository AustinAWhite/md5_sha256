#ifndef DISPATCH_H
# define DISPATCH_H

# include "./md5.h"
# include "./sha256.h"
# include <string.h>

extern void (*g_dispatch_funcs[])(char *input, u_int8_t type);
extern const char *g_dispatch_lookup[];

#endif
