#ifndef _DISPATCH_
#define _DISPATCH_

#include "./md5.h"
#include "./sha256.h"
#include <string.h>

static void  (*dispatch_funcs[])(t_container ssl, char *input) = {
    &md5,
    &sha256,
};

static const char   *dispatch_lookup[] = {
    "md5",
    "sha256",
    (char *)NULL,
};



/*
This is stupid get rid of this usage array
*/
static const char   *dispatch_usage[] = {
    "usage: md5 [-pqrtx] [-s string] [files ...]",
    "usage: sha256 [-pqrtx] [-s string] [files ...]",
};

#endif