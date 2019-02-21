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