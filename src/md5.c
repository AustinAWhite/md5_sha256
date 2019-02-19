#include "../inc/ssl.h"
#include "../inc/md5.h"

void md5_init_ctx(md5_ctx *ctx)
{
	ctx->state[0] = md5_a0;
	ctx->state[1] = md5_b0;
	ctx->state[2] = md5_c0;
	ctx->state[3] = md5_d0;
	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

void md5_update_damnnorm(md5_ctx *ctx,
					unsigned long *used, unsigned long *available,
					unsigned long *size, const void **message)
{
	*available = 64 - *used;
	if (*size < *available)
	{
		memcpy(&ctx->buffer[*used], *message, *size);
		return;
	}
	memcpy(&ctx->buffer[*used], *message, *available);
	*message = *message + *available;
	*size -= *available;
}

void md5_update(md5_ctx *ctx, const void *message, unsigned long size)
{
	u_int32_t cache_len;
	unsigned long used;
    unsigned long available;

	cache_len = ctx->count[0];
	if ((ctx->count[0] = (cache_len + size) & 0x1fffffff) < cache_len)
		ctx->count[1]++;
	ctx->count[1] += size >> 29;
	used = cache_len & 0x3f;
	if (used)
	{
		md5_update_damnnorm(ctx, &used, &available, &size, &message);
		md5_transform(ctx, ctx->buffer, 64);
	}
	if (size >= 64)
	{
		message = md5_transform(ctx, message, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}
	memcpy(ctx->buffer, message, size);
}

void md5_final(unsigned char *digest, md5_ctx *ctx)
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
	MD_OUT(&ctx->buffer[56], ctx->count[0])
	MD_OUT(&ctx->buffer[60], ctx->count[1])
	md5_transform(ctx, ctx->buffer, 64);
	MD_OUT(&digest[0], ctx->state[0])
	MD_OUT(&digest[4], ctx->state[1])
	MD_OUT(&digest[8], ctx->state[2])
	MD_OUT(&digest[12], ctx->state[3])
	memset(ctx, 0, sizeof(*ctx));
}

void md5(t_container container)
{
    md5_ctx ctx;
	u_int8_t digest[16];
    char *message;
	unsigned int len;

    if (container.message->content_size & IS_STR)
        message = container.message->content;
    else
        if ((message = readfile(container.message->content)) == NULL)
            return;
    len = ft_strlen(message);
	md5_init_ctx(&ctx);
	md5_update(&ctx, message, len);
	md5_final(digest, &ctx);
    print_hash(container, digest, 16);
}