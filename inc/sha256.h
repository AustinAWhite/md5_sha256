#ifndef _SHA_
#define _SHA_

#include "./global.h"
#include <inttypes.h>

#define CHUNK_SIZE 64
#define TOTAL_LEN 8
#define SHIFT_RIGHT(x, n)(x >> n | x << (32 - n))

typedef struct {
	u_int32_t w[64];
	u_int32_t s0;
	u_int32_t s1;
	u_int32_t ch;
	u_int32_t maj;
	u_int32_t temp1;
	u_int32_t temp2;
} sha256_vars;

typedef struct {
	u_int32_t state[8];
	u_int32_t count[2];
	u_int8_t chunk[CHUNK_SIZE];
	const uint8_t *message;
	int put_one;
	int complete;
} sha256_ctx;

enum sha256_buf_init {
	sha256_h0 = (u_int32_t)0x6a09e667,
	sha256_h1 = (u_int32_t)0xbb67ae85,
	sha256_h2 = (u_int32_t)0x3c6ef372,
	sha256_h3 = (u_int32_t)0xa54ff53a,
    sha256_h4 = (u_int32_t)0x510e527f,
	sha256_h5 = (u_int32_t)0x9b05688c,
	sha256_h6 = (u_int32_t)0x1f83d9ab,
	sha256_h7 = (u_int32_t)0x5be0cd19
};

void sha256(char *input, u_int8_t info);

#endif
