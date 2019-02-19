#ifndef _DISPATCH_
#define _DISPATCH_

#include "./md5.h"
#include "./sha256.h"
#include <string.h>

static void  (*dispatch_funcs[])(char *input, int cmd_idx, u_int8_t type) = {
    &md5,
    &sha256,
};

static const char   *dispatch_lookup[] = {
    "md5",
    "sha256",
    (char *)NULL,
};

#endif