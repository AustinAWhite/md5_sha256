#include "../inc/ssl.h"
#include "../inc/md5.h"

#define SET(n) (*(u_int32_t *)&ptr[(n) * 4])
#define GET(n) SET(n)

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z) (((x) ^ (y)) ^ (z))
#define H2(x, y, z) ((x) ^ ((y) ^ (z)))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define STEP(f, a, b, c, d, x, t, s) \
	(a) += f((b), (c), (d)) + (x) + (t); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
	(a) += (b);

#define MD_OUT(dst, src) \
	(dst)[0] = (unsigned char)(src); \
	(dst)[1] = (unsigned char)((src) >> 8); \
	(dst)[2] = (unsigned char)((src) >> 16); \
	(dst)[3] = (unsigned char)((src) >> 24);

uint32_t md5_k[64] = {
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

void md5_init_ctx(md5_ctx *ctx)
{
	ctx->state[0] = md5_a0;
	ctx->state[1] = md5_b0;
	ctx->state[2] = md5_c0;
	ctx->state[3] = md5_d0;

	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

static const void *md5_transform(md5_ctx *ctx,
					const void *data, unsigned long size) {
	const unsigned char *ptr;
	u_int32_t A;
	u_int32_t B;
	u_int32_t C;
	u_int32_t D;
	u_int32_t saved_A;
	u_int32_t saved_B;
	u_int32_t saved_C;
	u_int32_t saved_D;
	
	ptr = (const unsigned char *)data;
	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	do {
		saved_A = A;
		saved_B = B;
		saved_C = C;
		saved_D = D;

		STEP(F, A, B, C, D, SET( 0), md5_k[ 0], S11)
		STEP(F, D, A, B, C, SET( 1), md5_k[ 1], S12)
		STEP(F, C, D, A, B, SET( 2), md5_k[ 2], S13)
		STEP(F, B, C, D, A, SET( 3), md5_k[ 3], S14)
		STEP(F, A, B, C, D, SET( 4), md5_k[ 4], S11)
		STEP(F, D, A, B, C, SET( 5), md5_k[ 5], S12)
		STEP(F, C, D, A, B, SET( 6), md5_k[ 6], S13)
		STEP(F, B, C, D, A, SET( 7), md5_k[ 7], S14)
		STEP(F, A, B, C, D, SET( 8), md5_k[ 8], S11)
		STEP(F, D, A, B, C, SET( 9), md5_k[ 9], S12)
		STEP(F, C, D, A, B, SET(10), md5_k[10], S13)
		STEP(F, B, C, D, A, SET(11), md5_k[11], S14)
		STEP(F, A, B, C, D, SET(12), md5_k[12], S11)
		STEP(F, D, A, B, C, SET(13), md5_k[13], S12)
		STEP(F, C, D, A, B, SET(14), md5_k[14], S13)
		STEP(F, B, C, D, A, SET(15), md5_k[15], S14)

		STEP(G, A, B, C, D, GET( 1), md5_k[16], S21)
		STEP(G, D, A, B, C, GET( 6), md5_k[17], S22)
		STEP(G, C, D, A, B, GET(11), md5_k[18], S23)
		STEP(G, B, C, D, A, GET( 0), md5_k[19], S24)
		STEP(G, A, B, C, D, GET( 5), md5_k[20], S21)
		STEP(G, D, A, B, C, GET(10), md5_k[21], S22)
		STEP(G, C, D, A, B, GET(15), md5_k[22], S23)
		STEP(G, B, C, D, A, GET( 4), md5_k[23], S24)
		STEP(G, A, B, C, D, GET( 9), md5_k[24], S21)
		STEP(G, D, A, B, C, GET(14), md5_k[25], S22)
		STEP(G, C, D, A, B, GET( 3), md5_k[26], S23)
		STEP(G, B, C, D, A, GET( 8), md5_k[27], S24)
		STEP(G, A, B, C, D, GET(13), md5_k[28], S21)
		STEP(G, D, A, B, C, GET( 2), md5_k[29], S22)
		STEP(G, C, D, A, B, GET( 7), md5_k[30], S23)
		STEP(G, B, C, D, A, GET(12), md5_k[31], S24)

		STEP(H , A, B, C, D, GET( 5), md5_k[32], S31)
		STEP(H2, D, A, B, C, GET( 8), md5_k[33], S32)
		STEP(H , C, D, A, B, GET(11), md5_k[34], S33)
		STEP(H2, B, C, D, A, GET(14), md5_k[35], S34)
		STEP(H , A, B, C, D, GET( 1), md5_k[36], S31)
		STEP(H2, D, A, B, C, GET( 4), md5_k[37], S32)
		STEP(H , C, D, A, B, GET( 7), md5_k[38], S33)
		STEP(H2, B, C, D, A, GET(10), md5_k[39], S34)
		STEP(H , A, B, C, D, GET(13), md5_k[40], S31)
		STEP(H2, D, A, B, C, GET( 0), md5_k[41], S32)
		STEP(H , C, D, A, B, GET( 3), md5_k[42], S33)
		STEP(H2, B, C, D, A, GET( 6), md5_k[43], S34)
		STEP(H , A, B, C, D, GET( 9), md5_k[44], S31)
		STEP(H2, D, A, B, C, GET(12), md5_k[45], S32)
		STEP(H , C, D, A, B, GET(15), md5_k[46], S33)
		STEP(H2, B, C, D, A, GET( 2), md5_k[47], S34)

		STEP(I, A, B, C, D, GET( 0), md5_k[48], S41)
		STEP(I, D, A, B, C, GET( 7), md5_k[49], S42)
		STEP(I, C, D, A, B, GET(14), md5_k[50], S43)
		STEP(I, B, C, D, A, GET( 5), md5_k[51], S44)
		STEP(I, A, B, C, D, GET(12), md5_k[52], S41)
		STEP(I, D, A, B, C, GET( 3), md5_k[53], S42)
		STEP(I, C, D, A, B, GET(10), md5_k[54], S43)
		STEP(I, B, C, D, A, GET( 1), md5_k[55], S44)
		STEP(I, A, B, C, D, GET( 8), md5_k[56], S41)
		STEP(I, D, A, B, C, GET(15), md5_k[57], S42)
		STEP(I, C, D, A, B, GET( 6), md5_k[58], S43)
		STEP(I, B, C, D, A, GET(13), md5_k[59], S44)
		STEP(I, A, B, C, D, GET( 4), md5_k[60], S41)
		STEP(I, D, A, B, C, GET(11), md5_k[61], S42)
		STEP(I, C, D, A, B, GET( 2), md5_k[62], S43)
		STEP(I, B, C, D, A, GET( 9), md5_k[63], S44)
		
		A += saved_A;
		B += saved_B;
		C += saved_C;
		D += saved_D;
		ptr += 64;
	} while (size -= 64);

	ctx->state[0] = A;
	ctx->state[1] = B;
	ctx->state[2] = C;
	ctx->state[3] = D;
	return (ptr);
}

void md5_update(md5_ctx *ctx, const void *message, unsigned long size) {
	u_int32_t saved_lo;
	unsigned long used;
	unsigned long available;

	saved_lo = ctx->count[0];
	if ((ctx->count[0] = (saved_lo + size) & 0x1fffffff) < saved_lo) {
		ctx->count[1]++;
	}
	ctx->count[1] += size >> 29;
	used = saved_lo & 0x3f;
	if (used) {
		available = 64 - used;

		if (size < available) {
			memcpy(&ctx->buffer[used], message, size);
			return;
		}
		memcpy(&ctx->buffer[used], message, available);
		message = (const unsigned char *)message + available;
		size -= available;
		md5_transform(ctx, ctx->buffer, 64);
	}
	if (size >= 64) {
		message = md5_transform(ctx, message, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}
	memcpy(ctx->buffer, message, size);
}

void md5_final(unsigned char *digest, md5_ctx *ctx) {
	unsigned long used;
	unsigned long available;

	used = ctx->count[0] & 0x3f;
	ctx->buffer[used++] = 0x80;
	available = 64 - used;
	if (available < 8) {
		memset(&ctx->buffer[used], 0, available);
		md5_transform(ctx, ctx->buffer, 64);
		used = 0;
		available = 64;
	}
	memset(&ctx->buffer[used], 0, available - 8);
	ctx->count[0] <<= 3;
	MD_OUT(&ctx->buffer[56], ctx->count[0])
	MD_OUT(&ctx->buffer[60], ctx->count[1])
	md5_transform(ctx, ctx->buffer, 64);
	MD_OUT(&digest[0], ctx->state[0])
	MD_OUT(&digest[4], ctx->state[1])
	MD_OUT(&digest[8], ctx->state[2])
	MD_OUT(&digest[12], ctx->state[3])
	memset(ctx, 0, sizeof(*ctx));
}

void md5(char *input, u_int8_t info) {
	md5_ctx ctx;
	u_int8_t digest[16];
	char *message;
	unsigned int len;

	if (info & IS_STR) {
		message = input;
	}
	else if (info & IS_FILE) {
		if ((message = readfile(input)) == NULL) {
			return ;
		}
	}
	len = ft_strlen(message);
	md5_init_ctx(&ctx);
	md5_update(&ctx, message, len);
	md5_final(digest, &ctx);
	print_hash("MD5", input, digest, 16, info);
}
