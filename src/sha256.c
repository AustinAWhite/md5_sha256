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

static int calc_chunk(u_int8_t buffer[BLOCK_SIZE], sha256_ctx *ctx)
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

void sha_transform2_damnnorm(sha256_vars *v, u_int8_t *blk_cpy)
{
	int i;

	i = 0;
	while (i < 16)
	{
		(*v).w[i] = (u_int32_t)blk_cpy[0] << 24 | (u_int32_t)blk_cpy[1] << 16 |
						(u_int32_t)blk_cpy[2] << 8 | (u_int32_t)blk_cpy[3];
		blk_cpy += 4;
		i++;
	}
	while (i < 64)
	{
		(*v).s0 = SR((*v).w[i - 15], 7) ^ SR((*v).w[i - 15], 18) ^ ((*v).w[i - 15] >> 3);
		(*v).s1 = SR((*v).w[i - 2], 17) ^ SR((*v).w[i - 2], 19) ^ ((*v).w[i - 2] >> 10);
		(*v).w[i] = (*v).w[i - 16] + (*v).s0 + (*v).w[i - 7] + (*v).s1;
		i++;
	}
}

void sha_transform3_damnnorm(sha256_vars *v, u_int32_t wb[])
{
	int i;

	i = 0;
	while (i < 64)
	{
		(*v).s1 = SR(wb[4], 6) ^ SR(wb[4], 11) ^ SR(wb[4], 25);
		(*v).ch = (wb[4] & wb[5]) ^ (~wb[4] & wb[6]);
		(*v).temp1 = wb[7] + (*v).s1 + (*v).ch + sha256_k[i] + (*v).w[i];
		(*v).s0 = SR(wb[0], 2) ^ SR(wb[0], 13) ^ SR(wb[0], 22);
		(*v).maj = (wb[0] & wb[1]) ^ (wb[0] & wb[2]) ^ (wb[1] & wb[2]);
		(*v).temp2 = (*v).s0 + (*v).maj;
		wb[7] = wb[6];
		wb[6] = wb[5];
		wb[5] = wb[4];
		wb[4] = wb[3] + (*v).temp1;
		wb[3] = wb[2];
		wb[2] = wb[1];
		wb[1] = wb[0];
		wb[0] = (*v).temp1 + (*v).temp2;
		i++;
	}
}

void sha_transform4_damnnorm(sha256_ctx *ctx, u_int8_t hash[32])
{
	int i;
	int j;

	i = 0;
	j = 0;
	while (i < 8)
	{
        hash[j++] = (uint8_t) (ctx->state[i] >> 24);
        hash[j++] = (uint8_t) (ctx->state[i] >> 16);
        hash[j++] = (uint8_t) (ctx->state[i] >> 8);
        hash[j++] = (uint8_t) ctx->state[i];
		i++;
    }
}

void sha_transform(sha256_ctx *ctx, u_int8_t hash[32])
{
	int i;
	int j;
	sha256_vars v;
	u_int32_t wb[8];
	u_int8_t *blk_cpy;
	
	i = 0;
	j = 0;
	while (calc_chunk(ctx->block, ctx))
	{
		blk_cpy = ctx->block;
		memset(v.w, 0x00, sizeof v.w);
		sha_transform2_damnnorm(&v, blk_cpy);
		for (i = 0; i < 8; i++)
			wb[i] = ctx->state[i];
		sha_transform3_damnnorm(&v, wb);		
		for (j = 0; j < 8; j++)
			ctx->state[j] += wb[j];
	}
	sha_transform4_damnnorm(ctx, hash);
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
    sha_transform(&ctx, hash);
    print_hash(cmd_idx, input, info, hash, 32);
}