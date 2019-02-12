#ifndef _DISPATCH_
#define _DISPATCH_

#include "./ssl.h"
#include <string.h>

static void  (*g_dispatch_funcs[])(t_container ssl) = {
    &md5,
    //&sha256,
};

static const char   *g_dispatch_lookup[] = {
    "md5",
    //"sha256",
    (char *)NULL,
};

static const char   *g_dispatch_usage[] = {
    "usage: md5 [-pqrtx] [-s string] [files ...]",
    //"usage: sha256 [-pqrtx] [-s string] [files ...]",
};

#endif