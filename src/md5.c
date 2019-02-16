#include "../inc/ssl.h"

/*
Attribution:
    Based on Alexander Peslyak's MD5 implementation
    openwall.com - public domain sorouce code
*/

void MD5_Init(MD5_CTX *ctx)
{
	ctx->state[0] = md5_a0;
	ctx->state[1] = md5_b0;
	ctx->state[2] = md5_c0;
	ctx->state[3] = md5_d0;

	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

static const void *transform(MD5_CTX *ctx, const void *data, unsigned long size)
{
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

void MD5_Update(MD5_CTX *ctx, const void *data, unsigned long size)
{
	u_int32_t saved_lo;
	unsigned long used;
    unsigned long available;

	saved_lo = ctx->count[0];
	if ((ctx->count[0] = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->count[1]++;
	ctx->count[1] += size >> 29;
	used = saved_lo & 0x3f;
	if (used) {
		available = 64 - used;

		if (size < available) {
			ft_memcpy(&ctx->buffer[used], data, size);
			return;
		}
		ft_memcpy(&ctx->buffer[used], data, available);
		data = (const unsigned char *)data + available;
		size -= available;
		transform(ctx, ctx->buffer, 64);
	}
	if (size >= 64) {
		data = transform(ctx, data, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}
	ft_memcpy(ctx->buffer, data, size);
}

void MD5_Final(unsigned char *result, MD5_CTX *ctx)
{
	unsigned long used;
    unsigned long available;

	used = ctx->count[0] & 0x3f;
	ctx->buffer[used++] = 0x80;
	available = 64 - used;
	if (available < 8) {
		ft_memset(&ctx->buffer[used], 0, available);
		transform(ctx, ctx->buffer, 64);
		used = 0;
		available = 64;
	}
	ft_memset(&ctx->buffer[used], 0, available - 8);
	ctx->count[0] <<= 3;
	OUT(&ctx->buffer[56], ctx->count[0])
	OUT(&ctx->buffer[60], ctx->count[1])
	transform(ctx, ctx->buffer, 64);
	OUT(&result[0], ctx->state[0])
	OUT(&result[4], ctx->state[1])
	OUT(&result[8], ctx->state[2])
	OUT(&result[12], ctx->state[3])
	ft_memset(ctx, 0, sizeof(*ctx));
}

void digest(t_container container)
{
    MD5_CTX context;
	unsigned char digest[16];
    char *message;
	unsigned int len;

    if (container.message->content_size & IS_STR)
        message = container.message->content;
    else
        if ((message = readfile(container.message->content)) == NULL)
            return;
    len = ft_strlen(message);
	MD5_Init (&context);
	MD5_Update (&context, message, len);
	MD5_Final (digest, &context);
    print_hash(container, digest, 16);
}

void md5(t_container container)
{
    struct stat fstat;
    while (container.message) {
        if (container.message->content_size & IS_STR)
            digest(container);
        else if (container.message->content_size & IS_FILE) {
            if (access(container.message->content, F_OK) != -1) {
                stat(container.message->content, &fstat);
                if (S_ISDIR(fstat.st_mode))
                    file_error("md5", container.message->content, "Is a directory");
                else
                    digest(container);
            }
            else
                file_error("md5", container.message->content, "No such file or directory");
        }
        container.message = container.message->next;
    }
}