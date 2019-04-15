#include "../inc/ssl.h"
#include "../inc/md5.h"

uint32_t g_md5_k[64] = {
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

void	md5_update(t_md5_ctx *ctx, const void *message, unsigned long size)
{
	u_int32_t		cache_len;
	unsigned long	fucknorm[2];

	cache_len = ctx->count[0];
	if ((ctx->count[0] = (cache_len + size) & 0x1fffffff) < cache_len)
		ctx->count[1]++;
	ctx->count[1] += size >> 29;
	fucknorm[0] = cache_len & 0x3f;
	if (fucknorm[0])
	{
		md5_update_damnnorm(ctx, fucknorm, &size, &message);
		md5_transform(ctx, ctx->buffer, 64);
	}
	if (size >= 64)
	{
		message = md5_transform(ctx, message, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}
	memcpy(ctx->buffer, message, size);
}

void	transform_and_out_damnnorm(t_md5_ctx *ctx, unsigned char *digest)
{
	int arr[4];

	arr[0] = 0;
	arr[1] = 56;
	arr[2] = 0;
	arr[3] = 0;
	while (arr[0] < 2)
	{
		ctx->buffer[arr[1]++] = (unsigned char)(ctx->count[arr[0]]);
		ctx->buffer[arr[1]++] = (unsigned char)((ctx->count[arr[0]]) >> 8);
		ctx->buffer[arr[1]++] = (unsigned char)((ctx->count[arr[0]]) >> 16);
		ctx->buffer[arr[1]++] = (unsigned char)((ctx->count[arr[0]]) >> 24);
		arr[0]++;
	}
	md5_transform(ctx, ctx->buffer, 64);
	while (arr[2] < 4)
	{
		digest[arr[3]++] = (unsigned char)(ctx->state[arr[2]]);
		digest[arr[3]++] = (unsigned char)((ctx->state[arr[2]]) >> 8);
		digest[arr[3]++] = (unsigned char)((ctx->state[arr[2]]) >> 16);
		digest[arr[3]++] = (unsigned char)((ctx->state[arr[2]]) >> 24);
		arr[2]++;
	}
	memset(ctx, 0, sizeof(*ctx));
}

void	md5_final(unsigned char *digest, t_md5_ctx *ctx)
{
	unsigned long used;
	unsigned long available;

	used = ctx->count[0] & 0x3f;
	ctx->buffer[used++] = 0x80;
	available = 64 - used;
	if (available < 8)
	{
		memset(&ctx->buffer[used], 0, available);
		md5_transform(ctx, ctx->buffer, 64);
		used = 0;
		available = 64;
	}
	memset(&ctx->buffer[used], 0, available - 8);
	ctx->count[0] <<= 3;
	transform_and_out_damnnorm(ctx, digest);
}

void	md5(char *input, int cmd_idx, u_int8_t type)
{
	t_md5_ctx	ctx;
	u_int8_t	digest[16];
	char		*message;

	if (type & IS_STR)
		message = input;
	else if (type & IS_FILE)
		if ((message = readfile(input)) == NULL)
			return ;
	md5_init_ctx(&ctx);
	md5_update(&ctx, message, ft_strlen(message));
	md5_final(digest, &ctx);
	print2_damnnorm(cmd_idx, input, type);
	print_hash(input, type, digest, 16);
	ft_putendl("");
}
