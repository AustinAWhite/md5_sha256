#ifndef _MD5_
#define _MD5_

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

typedef struct  s_md5_ctx
{
    u_int32_t   state[4];
    u_int32_t   count[2];
    u_int8_t    buffer[64];
    u_int32_t   block[16];
}               t_md5_ctx;

extern const unsigned char *g_ptr;

static uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

enum md5_buf_init {
    md5_a0 = (uint32_t)0x67452301,
    md5_b0 = (uint32_t)0xefcdab89,
    md5_c0 = (uint32_t)0x98badcfe,
    md5_d0 = (uint32_t)0x10325476
};

void        md5(char *input, int cmd_idx, u_int8_t type);
void        move_data(u_int32_t *arr1, u_int32_t *arr2);
const void  *md5_transform(t_md5_ctx *ctx,
                        const void *data, unsigned long size);
void        md5_init_ctx(t_md5_ctx *ctx);
void        md5_update_damnnorm(t_md5_ctx *ctx,
					unsigned long fucknorm[],
					unsigned long *size, const void **message);
void        round1_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s);
void        round2_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s);
void        round3_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s);
void        round3_logic_H2(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s);
void        round4_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s);
#endif