#include "../inc/ssl.h"

/*
Attribution:
    Based on amosnier sha256 implementation
    github.com/amosnier
*/

static inline uint32_t right_rot(uint32_t value, unsigned int count)
{
	return value >> count | value << (32 - count);
}

static void init_buf_state(struct buffer_state *state, const void * input, size_t len)
{
	state->p = input;
	state->len = len;
	state->total_len = len;
	state->single_one_delivered = 0;
	state->total_len_delivered = 0;
}

static int calc_chunk(uint8_t chunk[CHUNK_SIZE], struct buffer_state * state)
{
	size_t space_in_chunk;

	if (state->total_len_delivered) {
		return 0;
	}
	if (state->len >= CHUNK_SIZE) {
		memcpy(chunk, state->p, CHUNK_SIZE);
		state->p += CHUNK_SIZE;
		state->len -= CHUNK_SIZE;
		return 1;
	}
	memcpy(chunk, state->p, state->len);
	chunk += state->len;
	space_in_chunk = CHUNK_SIZE - state->len;
	state->p += state->len;
	state->len = 0;
	if (!state->single_one_delivered) {
		*chunk++ = 0x80;
		space_in_chunk -= 1;
		state->single_one_delivered = 1;
	}
	if (space_in_chunk >= TOTAL_LEN_LEN) {
		const size_t left = space_in_chunk - TOTAL_LEN_LEN;
		size_t len = state->total_len;
		int i;
		memset(chunk, 0x00, left);
		chunk += left;
		chunk[7] = (uint8_t) (len << 3);
		len >>= 5;
		for (i = 6; i >= 0; i--) {
			chunk[i] = (uint8_t) len;
			len >>= 8;
		}
		state->total_len_delivered = 1;
	} else {
		memset(chunk, 0x00, space_in_chunk);
	}
	return 1;
}

void sha_transform(uint8_t hash[32], const void *input, size_t len)
{
	uint32_t h[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	int i, j;
	uint8_t chunk[64];
	struct buffer_state state;

	init_buf_state(&state, input, len);
	while (calc_chunk(chunk, &state)) {
		uint32_t ah[8];
		uint32_t w[64];
		const uint8_t *p = chunk;
		memset(w, 0x00, sizeof w);
		for (i = 0; i < 16; i++) {
			w[i] = (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 |
				(uint32_t) p[2] << 8 | (uint32_t) p[3];
			p += 4;
		}
		for (i = 16; i < 64; i++) {
			const uint32_t s0 = right_rot(w[i - 15], 7) ^ right_rot(w[i - 15], 18) ^ (w[i - 15] >> 3);
			const uint32_t s1 = right_rot(w[i - 2], 17) ^ right_rot(w[i - 2], 19) ^ (w[i - 2] >> 10);
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}
		for (i = 0; i < 8; i++)
			ah[i] = h[i];
		for (i = 0; i < 64; i++) {
			const uint32_t s1 = right_rot(ah[4], 6) ^ right_rot(ah[4], 11) ^ right_rot(ah[4], 25);
			const uint32_t ch = (ah[4] & ah[5]) ^ (~ah[4] & ah[6]);
			const uint32_t temp1 = ah[7] + s1 + ch + sha256_k[i] + w[i];
			const uint32_t s0 = right_rot(ah[0], 2) ^ right_rot(ah[0], 13) ^ right_rot(ah[0], 22);
			const uint32_t maj = (ah[0] & ah[1]) ^ (ah[0] & ah[2]) ^ (ah[1] & ah[2]);
			const uint32_t temp2 = s0 + maj;

			ah[7] = ah[6];
			ah[6] = ah[5];
			ah[5] = ah[4];
			ah[4] = ah[3] + temp1;
			ah[3] = ah[2];
			ah[2] = ah[1];
			ah[1] = ah[0];
			ah[0] = temp1 + temp2;
		}
		for (i = 0; i < 8; i++)
			h[i] += ah[i];
	}
	for (i = 0, j = 0; i < 8; i++)
	{
		hash[j++] = (uint8_t) (h[i] >> 24);
		hash[j++] = (uint8_t) (h[i] >> 16);
		hash[j++] = (uint8_t) (h[i] >> 8);
		hash[j++] = (uint8_t) h[i];
	}
}		

void sha256_print(t_container container, unsigned char hash[])
{
    if (!(container.flags & FLG_Q) && !(container.flags & FLG_R) && !(container.message->content_size & P_APPEND)) {
        if (container.message->content_size & IS_STR) {
            ft_putstr("SHA256 (\"");
            ft_putstr(container.message->content);
            ft_putstr("\") = ");
        }
        else if (container.message->content_size & IS_FILE) {
            ft_putstr("SHA256 (");
            ft_putstr(container.message->content);
            ft_putstr(") = ");
        }
    }
    if ((container.flags & FLG_P) && (container.message->content_size & P_APPEND))
        ft_putstr(container.message->content);
    for (int i = 0; i < 32; i++) {
        if (hash[i] < 0xF)
            ft_putchar('0');       
        ft_putstr(ft_itoa_base(hash[i], 16));
    }
    if (container.flags & FLG_R && !(container.message->content_size & P_APPEND) && !(container.flags & FLG_Q)) {
        if (container.message->content_size & IS_STR) {
            ft_putstr(" \"");
            ft_putstr(container.message->content);
            ft_putstr("\"");
        }
        else if (container.message->content_size & IS_FILE) {
            ft_putstr(" ");
            ft_putstr(container.message->content);
        }
    }
    ft_putendl("");
}

void calc_hash(t_container container)
{
    uint8_t hash[32];
	char hash_string[65];
	unsigned int len;
    char *message;

    if (container.message->content_size & IS_STR)
        message = container.message->content;
    else
        if ((message = readfile(container.message->content)) == NULL)
            return;
    len = ft_strlen(message);
    sha_transform(hash, message, len);
    sha256_print(container, hash);
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
                    file_error("md5", container.message->content, "Is a directory");
                else
                    calc_hash(container);
            }
            else
                file_error("md5", container.message->content, "No such file or directory");
        }
        container.message = container.message->next;
    }
}