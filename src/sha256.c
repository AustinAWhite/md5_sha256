#include "../inc/ssl.h"

/*
Attribution:
    Based on amosnier sha256 implementation
    github.com/amosnier
*/

static void init_buf_state(sha256_ctx *ctx, const void *message, size_t len)
{
	ctx->state[0] = sha256_h0;
	ctx->state[1] = sha256_h1;
	ctx->state[2] = sha256_h2;
	ctx->state[3] = sha256_h3;
	ctx->state[4] = sha256_h4;
	ctx->state[5] = sha256_h5;
	ctx->state[6] = sha256_h6;
	ctx->state[7] = sha256_h7;
	ctx->message = message;
	ctx->len = len;
	ctx->total_len = len;
	ctx->single_one_delivered = 0;
	ctx->complete = 0;
}

static int calc_chunk(u_int8_t buffer[CHUNK_SIZE], sha256_ctx *ctx)
{
	size_t space_left;

	if (ctx->complete) {
		return 0;
	}
	if (ctx->len >= CHUNK_SIZE) {
		memcpy(buffer, ctx->message, CHUNK_SIZE);
		ctx->message += CHUNK_SIZE;
		ctx->len -= CHUNK_SIZE;
		return 1;
	}
	memcpy(buffer, ctx->message, ctx->len);
	buffer += ctx->len;
	space_left = CHUNK_SIZE - ctx->len;
	ctx->message += ctx->len;
	ctx->len = 0;
	if (!ctx->single_one_delivered) {
		*buffer++ = 0x80;
		space_left -= 1;
		ctx->single_one_delivered = 1;
	}
	if (space_left >= TOTAL_LEN) {
		const size_t left = space_left - TOTAL_LEN;
		size_t len = ctx->total_len;
		int i;
		memset(buffer, 0x00, left);
		buffer += left;
		buffer[7] = (u_int8_t)(len << 3);
		len >>= 5;
		for (i = 6; i >= 0; i--) {
			buffer[i] = (u_int8_t)len;
			len >>= 8;
		}
		ctx->complete = 1;
	} else {
		memset(buffer, 0x00, space_left);
	}
	return 1;
}

void sha_transform(sha256_ctx *ctx, u_int8_t hash[32])
{
	int i, j;
	sha256_vars vars;
	u_int32_t w_bufs[8];
	const u_int8_t *chunk_cpy;
	
	while (calc_chunk(ctx->chunk, ctx)) {
		chunk_cpy = ctx->chunk;
		memset(vars.w, 0x00, sizeof vars.w);
		for (i = 0; i < 16; i++) {
			vars.w[i] = (u_int32_t)chunk_cpy[0] << 24 | (u_int32_t)chunk_cpy[1] << 16 |
							(u_int32_t)chunk_cpy[2] << 8 | (u_int32_t)chunk_cpy[3];
			chunk_cpy += 4;
		}
		for (i = 16; i < 64; i++) {
			vars.s0 = SHIFT_RIGHT(vars.w[i - 15], 7) ^ SHIFT_RIGHT(vars.w[i - 15], 18) ^ (vars.w[i - 15] >> 3);
			vars.s1 = SHIFT_RIGHT(vars.w[i - 2], 17) ^ SHIFT_RIGHT(vars.w[i - 2], 19) ^ (vars.w[i - 2] >> 10);
			vars.w[i] = vars.w[i - 16] + vars.s0 + vars.w[i - 7] + vars.s1;
		}
		for (i = 0; i < 8; i++)
			w_bufs[i] = ctx->state[i];
		for (i = 0; i < 64; i++) {
			vars.s1 = SHIFT_RIGHT(w_bufs[4], 6) ^ SHIFT_RIGHT(w_bufs[4], 11) ^ SHIFT_RIGHT(w_bufs[4], 25);
			vars.ch = (w_bufs[4] & w_bufs[5]) ^ (~w_bufs[4] & w_bufs[6]);
			vars.temp1 = w_bufs[7] + vars.s1 + vars.ch + sha256_k[i] + vars.w[i];
			vars.s0 = SHIFT_RIGHT(w_bufs[0], 2) ^ SHIFT_RIGHT(w_bufs[0], 13) ^ SHIFT_RIGHT(w_bufs[0], 22);
			vars.maj = (w_bufs[0] & w_bufs[1]) ^ (w_bufs[0] & w_bufs[2]) ^ (w_bufs[1] & w_bufs[2]);
			vars.temp2 = vars.s0 + vars.maj;

			w_bufs[7] = w_bufs[6];
			w_bufs[6] = w_bufs[5];
			w_bufs[5] = w_bufs[4];
			w_bufs[4] = w_bufs[3] + vars.temp1;
			w_bufs[3] = w_bufs[2];
			w_bufs[2] = w_bufs[1];
			w_bufs[1] = w_bufs[0];
			w_bufs[0] = vars.temp1 + vars.temp2;
		}
		for (i = 0; i < 8; i++)
			ctx->state[i] += w_bufs[i];
	}
	for (i = 0, j = 0; i < 8; i++)
    {
        hash[j++] = (uint8_t) (ctx->state[i] >> 24);
        hash[j++] = (uint8_t) (ctx->state[i] >> 16);
        hash[j++] = (uint8_t) (ctx->state[i] >> 8);
        hash[j++] = (uint8_t) ctx->state[i];
    }
}	

void sha256(t_container container)
{
	sha256_ctx ctx;
    u_int8_t hash[32];
	char *message;
	unsigned int len;

    if (container.message->content_size & IS_STR)
        message = container.message->content;
    else
        if ((message = readfile(container.message->content)) == NULL)
            return;
    len = ft_strlen(message);
	init_buf_state(&ctx, message, len);
    sha_transform(&ctx, hash);
    print_hash(container, hash, 32);
}