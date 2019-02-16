#include "../inc/ssl.h"

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
	ctx->p = input;
	ctx->len = len;
	ctx->total_len = len;
	ctx->single_one_delivered = 0;
	ctx->total_len_delivered = 0;
}

static int calc_chunk(uint8_t buffer[CHUNK_SIZE], sha256_ctx *ctx)
{
	size_t space_in_chunk;

	if (ctx->total_len_delivered) {
		return 0;
	}
	if (ctx->len >= CHUNK_SIZE) {
		memcpy(buffer, ctx->p, CHUNK_SIZE);
		ctx->p += CHUNK_SIZE;
		ctx->len -= CHUNK_SIZE;
		return 1;
	}
	memcpy(buffer, ctx->p, ctx->len);
	buffer += ctx->len;
	space_in_chunk = CHUNK_SIZE - ctx->len;
	ctx->p += ctx->len;
	ctx->len = 0;
	if (!ctx->single_one_delivered) {
		*buffer++ = 0x80;
		space_in_chunk -= 1;
		ctx->single_one_delivered = 1;
	}
	if (space_in_chunk >= TOTAL_LEN_LEN) {
		const size_t left = space_in_chunk - TOTAL_LEN_LEN;
		size_t len = ctx->total_len;
		int i;
		memset(buffer, 0x00, left);
		buffer += left;
		buffer[7] = (uint8_t) (len << 3);
		len >>= 5;
		for (i = 6; i >= 0; i--) {
			buffer[i] = (uint8_t) len;
			len >>= 8;
		}
		ctx->total_len_delivered = 1;
	} else {
		memset(buffer, 0x00, space_in_chunk);
	}
	return 1;
}

void sha_transform(sha256_ctx *ctx, uint8_t hash[32], const void *input, size_t len)
{
	int i, j;
	u_int32_t w_bufs[8];
	const u_int8_t *ctxbuf_cpy; 
	
	while (calc_chunk(ctx->buffer, ctx)) {
		uint32_t w[64];
		ctxbuf_cpy = ctx->buffer;
		memset(w, 0x00, sizeof w);
		for (i = 0; i < 16; i++) {
			w[i] = (uint32_t) ctxbuf_cpy[0] << 24 | (uint32_t) ctxbuf_cpy[1] << 16 |
							(uint32_t) ctxbuf_cpy[2] << 8 | (uint32_t) ctxbuf_cpy[3];
			ctxbuf_cpy += 4;
		}
		for (i = 16; i < 64; i++) {
			const uint32_t s0 = SHIFT_RIGHT(w[i - 15], 7) ^ SHIFT_RIGHT(w[i - 15], 18) ^ (w[i - 15] >> 3);
			const uint32_t s1 = SHIFT_RIGHT(w[i - 2], 17) ^ SHIFT_RIGHT(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		for (i = 0; i < 8; i++)
			w_bufs[i] = ctx->state[i];
		for (i = 0; i < 64; i++) {
			const uint32_t s1 = SHIFT_RIGHT(w_bufs[4], 6) ^ SHIFT_RIGHT(w_bufs[4], 11) ^ SHIFT_RIGHT(w_bufs[4], 25);
			const uint32_t ch = (w_bufs[4] & w_bufs[5]) ^ (~w_bufs[4] & w_bufs[6]);
			const uint32_t temp1 = w_bufs[7] + s1 + ch + sha256_k[i] + w[i];
			const uint32_t s0 = SHIFT_RIGHT(w_bufs[0], 2) ^ SHIFT_RIGHT(w_bufs[0], 13) ^ SHIFT_RIGHT(w_bufs[0], 22);
			const uint32_t maj = (w_bufs[0] & w_bufs[1]) ^ (w_bufs[0] & w_bufs[2]) ^ (w_bufs[1] & w_bufs[2]);
			const uint32_t temp2 = s0 + maj;

			w_bufs[7] = w_bufs[6];
			w_bufs[6] = w_bufs[5];
			w_bufs[5] = w_bufs[4];
			w_bufs[4] = w_bufs[3] + temp1;
			w_bufs[3] = w_bufs[2];
			w_bufs[2] = w_bufs[1];
			w_bufs[1] = w_bufs[0];
			w_bufs[0] = temp1 + temp2;
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

void calc_hash(t_container container)
{
	sha256_ctx ctx;
    uint8_t hash[32];
	char *message;
	unsigned int len;

    if (container.message->content_size & IS_STR)
        message = container.message->content;
    else
        if ((message = readfile(container.message->content)) == NULL)
            return;
    len = ft_strlen(message);
	init_buf_state(&ctx, message, len);
    sha_transform(&ctx, hash, message, len);
    print_hash(container, hash, 32);
}

void sha256(t_container container)
{
    struct stat fstat;

    while (container.message) {
        if (container.message->content_size & IS_STR)
            calc_hash(container);
        else if (container.message->content_size & IS_FILE) {
            if (access(container.message->content, F_OK) != -1) {
                stat(container.message->content, &fstat);
                if (S_ISDIR(fstat.st_mode))
                    file_error("sha256", container.message->content,
											"Is a directory");
                else
                    calc_hash(container);
            }
            else
                file_error("sha256", container.message->content,
											"No such file or directory");
        }
        container.message = container.message->next;
    }
}