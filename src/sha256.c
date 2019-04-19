#include "../inc/ssl.h"
#include "../inc/sha256.h"

const u_int32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

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
	ctx->count[0] = len;
	ctx->count[1] = len;
	ctx->put_one = 0;
	ctx->complete = 0;
}

static int calc_chunk(u_int8_t buffer[CHUNK_SIZE], sha256_ctx *ctx)
{
	size_t space_left;
	size_t left;
	u_int32_t len;

	if (ctx->complete) {
		return 0;
	}
	if (ctx->count[0] >= CHUNK_SIZE) {
		memcpy(buffer, ctx->message, CHUNK_SIZE);
		ctx->message += CHUNK_SIZE;
		ctx->count[0] -= CHUNK_SIZE;
		return 1;
	}
	memcpy(buffer, ctx->message, ctx->count[0]);
	buffer += ctx->count[0];
	space_left = CHUNK_SIZE - ctx->count[0];
	ctx->message += ctx->count[0];
	ctx->count[0] = 0;
	if (!ctx->put_one) {
		*buffer++ = 0x80;
		space_left -= 1;
		ctx->put_one = 1;
	}
	if (space_left >= TOTAL_LEN) {
		left = space_left - TOTAL_LEN;
		len = ctx->count[1];
		memset(buffer, 0x00, left);
		buffer += left;
		buffer[7] = (u_int8_t)(len << 3);
		len >>= 5;
		for (int i = 6; i >= 0; i--) {
			buffer[i] = (u_int8_t)len;
			len >>= 8;
		}
		ctx->complete = 1;
	}
	else
		memset(buffer, 0x00, space_left);
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
	for (i = 0, j = 0; i < 8; i++) {
        hash[j++] = (uint8_t) (ctx->state[i] >> 24);
        hash[j++] = (uint8_t) (ctx->state[i] >> 16);
        hash[j++] = (uint8_t) (ctx->state[i] >> 8);
        hash[j++] = (uint8_t) ctx->state[i];
    }
}	

void sha256(char *input, u_int8_t info)
{
	sha256_ctx ctx;
    u_int8_t hash[32];
	char *message;
	unsigned int len;

    if (info & IS_STR)
        message = input;
    else
        if ((message = readfile(input)) == NULL)
            return;
    len = ft_strlen(message);
	init_buf_state(&ctx, message, len);
    sha_transform(&ctx, hash);
    print_hash("SHA256", input, hash, 32, info);
}