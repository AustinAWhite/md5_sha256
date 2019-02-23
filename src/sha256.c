#include "../inc/ssl.h"
#include "../inc/sha256.h"

/*
Attribution:
    Based on amosnier sha256 implementation
    github.com/amosnier
*/

static void init_buf_state(sha256_ctx *ctx, const void *input, size_t len)
{
	ctx->state[0] = sha256_h0;
	ctx->state[1] = sha256_h1;
	ctx->state[2] = sha256_h2;
	ctx->state[3] = sha256_h3;
	ctx->state[4] = sha256_h4;
	ctx->state[5] = sha256_h5;
	ctx->state[6] = sha256_h6;
	ctx->state[7] = sha256_h7;
	ctx->message = input;
	ctx->count[0] = len;
	ctx->count[1] = len;
	ctx->put_one = 0;
	ctx->complete = 0;
}

int calc_chunk(u_int8_t buffer[BLOCK_SIZE], sha256_ctx *ctx)
{
	size_t space_left;
	size_t left;
	u_int32_t len;

	if (ctx->complete)
		return 0;
	if (ctx->count[0] >= BLOCK_SIZE)
	{
		memcpy(buffer, ctx->message, BLOCK_SIZE);
		ctx->message += BLOCK_SIZE;
		ctx->count[0] -= BLOCK_SIZE;
		return 1;
	}
	memcpy(buffer, ctx->message, ctx->count[0]);
	buffer += ctx->count[0];
	space_left = BLOCK_SIZE - ctx->count[0];
	ctx->message += ctx->count[0];
	ctx->count[0] = 0;
	if (!ctx->put_one)
	{
		*buffer++ = 0x80;
		space_left -= 1;
		ctx->put_one = 1;
	}
	if (space_left >= TOTAL_LEN)
	{
		left = space_left - TOTAL_LEN;
		len = ctx->count[1];
		memset(buffer, 0x00, left);
		buffer += left;
		buffer[7] = (u_int8_t)(len << 3);
		len >>= 5;
		for (int i = 6; i >= 0; i--)
		{
			buffer[i] = (u_int8_t)len;
			len >>= 8;
		}
		ctx->complete = 1;
	}
	else
		memset(buffer, 0x00, space_left);
	return 1;
}

void sha256(char *input, int cmd_idx, u_int8_t info)
{
	sha256_ctx ctx;
    u_int8_t hash[32];
	char *message;
	unsigned int len;

    if (info & IS_STR)
        message = input;
    else if (info & IS_FILE)
        if ((message = readfile(input)) == NULL)
            return ;
    len = ft_strlen(message);
	init_buf_state(&ctx, message, len);
    sha256_transform(&ctx, hash);
    print_hash(cmd_idx, input, info, hash, 32);
}