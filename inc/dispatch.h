#ifndef _DISPATCH_
#define _DISPATCH_

#include "./md5.h"
#include "./sha256.h"
#include <string.h>

static void  (*dispatch_funcs[])(t_container ssl) = {
    &md5,
    &sha256,
    //&sha224,
    //&sha384,
    //&sha512,
};

static const char   *dispatch_lookup[] = {
    "md5",
    "sha256",
    //"sha224",
    //"sha384",
    //"sha512",
    (char *)NULL,
};



/*
This is stupid get rid of this usage array
*/
static const char   *dispatch_usage[] = {
    "usage: md5 [-pqrtx] [-s string] [files ...]",
    "usage: sha256 [-pqrtx] [-s string] [files ...]",
    //"usage: sha224 [-pqrtx] [-s string] [files ...]",
    //"usage: sha384 [-pqrtx] [-s string] [files ...]",
    //"usage: sha512 [-pqrtx] [-s string] [files ...]",
};

#endif