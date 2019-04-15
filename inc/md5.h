#ifndef _MD5_
#define _MD5_

#include "./global.h"
#include <inttypes.h>

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

typedef struct {
    u_int32_t state[4];
    u_int32_t count[2];
    u_int8_t buffer[64];
    u_int32_t block[16];
} md5_ctx;

enum md5_buf_init {
    md5_a0 = (uint32_t)0x67452301,
    md5_b0 = (uint32_t)0xefcdab89,
    md5_c0 = (uint32_t)0x98badcfe,
    md5_d0 = (uint32_t)0x10325476
};

void        md5(char *input, u_int8_t type);

#endif