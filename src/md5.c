#include "../inc/ssl.h"

/*
Attribution:
    Based on Alexander Peslyak's MD5 implementation
    openwall.com - public domain sorouce code
*/

void MD5_Init(MD5_CTX *ctx)
{
	ctx->state[0] = a0;
	ctx->state[1] = b0;
	ctx->state[2] = c0;
	ctx->state[3] = d0;

	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

static const void *transform(MD5_CTX *ctx, const void *data, unsigned long size)
{
	const unsigned char *ptr;
	MD5_u32plus A;
    MD5_u32plus B;
    MD5_u32plus C;
    MD5_u32plus D;
	MD5_u32plus saved_A;
    MD5_u32plus saved_B;
    MD5_u32plus saved_C;
    MD5_u32plus saved_D;

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

		STEP(F, A, B, C, D, SET( 0), k[ 0], S11)
		STEP(F, D, A, B, C, SET( 1), k[ 1], S12)
		STEP(F, C, D, A, B, SET( 2), k[ 2], S13)
		STEP(F, B, C, D, A, SET( 3), k[ 3], S14)
		STEP(F, A, B, C, D, SET( 4), k[ 4], S11)
		STEP(F, D, A, B, C, SET( 5), k[ 5], S12)
		STEP(F, C, D, A, B, SET( 6), k[ 6], S13)
		STEP(F, B, C, D, A, SET( 7), k[ 7], S14)
		STEP(F, A, B, C, D, SET( 8), k[ 8], S11)
		STEP(F, D, A, B, C, SET( 9), k[ 9], S12)
		STEP(F, C, D, A, B, SET(10), k[10], S13)
		STEP(F, B, C, D, A, SET(11), k[11], S14)
		STEP(F, A, B, C, D, SET(12), k[12], S11)
		STEP(F, D, A, B, C, SET(13), k[13], S12)
		STEP(F, C, D, A, B, SET(14), k[14], S13)
		STEP(F, B, C, D, A, SET(15), k[15], S14)

		STEP(G, A, B, C, D, GET( 1), k[16], S21)
		STEP(G, D, A, B, C, GET( 6), k[17], S22)
		STEP(G, C, D, A, B, GET(11), k[18], S23)
		STEP(G, B, C, D, A, GET( 0), k[19], S24)
		STEP(G, A, B, C, D, GET( 5), k[20], S21)
		STEP(G, D, A, B, C, GET(10), k[21], S22)
		STEP(G, C, D, A, B, GET(15), k[22], S23)
		STEP(G, B, C, D, A, GET( 4), k[23], S24)
		STEP(G, A, B, C, D, GET( 9), k[24], S21)
		STEP(G, D, A, B, C, GET(14), k[25], S22)
		STEP(G, C, D, A, B, GET( 3), k[26], S23)
		STEP(G, B, C, D, A, GET( 8), k[27], S24)
		STEP(G, A, B, C, D, GET(13), k[28], S21)
		STEP(G, D, A, B, C, GET( 2), k[29], S22)
		STEP(G, C, D, A, B, GET( 7), k[30], S23)
		STEP(G, B, C, D, A, GET(12), k[31], S24)

		STEP(H , A, B, C, D, GET( 5), k[32], S31)
		STEP(H2, D, A, B, C, GET( 8), k[33], S32)
		STEP(H , C, D, A, B, GET(11), k[34], S33)
		STEP(H2, B, C, D, A, GET(14), k[35], S34)
		STEP(H , A, B, C, D, GET( 1), k[36], S31)
		STEP(H2, D, A, B, C, GET( 4), k[37], S32)
		STEP(H , C, D, A, B, GET( 7), k[38], S33)
		STEP(H2, B, C, D, A, GET(10), k[39], S34)
		STEP(H , A, B, C, D, GET(13), k[40], S31)
		STEP(H2, D, A, B, C, GET( 0), k[41], S32)
		STEP(H , C, D, A, B, GET( 3), k[42], S33)
		STEP(H2, B, C, D, A, GET( 6), k[43], S34)
		STEP(H , A, B, C, D, GET( 9), k[44], S31)
		STEP(H2, D, A, B, C, GET(12), k[45], S32)
		STEP(H , C, D, A, B, GET(15), k[46], S33)
		STEP(H2, B, C, D, A, GET( 2), k[47], S34)

		STEP(I, A, B, C, D, GET( 0), k[48], S41)
		STEP(I, D, A, B, C, GET( 7), k[49], S42)
		STEP(I, C, D, A, B, GET(14), k[50], S43)
		STEP(I, B, C, D, A, GET( 5), k[51], S44)
		STEP(I, A, B, C, D, GET(12), k[52], S41)
		STEP(I, D, A, B, C, GET( 3), k[53], S42)
		STEP(I, C, D, A, B, GET(10), k[54], S43)
		STEP(I, B, C, D, A, GET( 1), k[55], S44)
		STEP(I, A, B, C, D, GET( 8), k[56], S41)
		STEP(I, D, A, B, C, GET(15), k[57], S42)
		STEP(I, C, D, A, B, GET( 6), k[58], S43)
		STEP(I, B, C, D, A, GET(13), k[59], S44)
		STEP(I, A, B, C, D, GET( 4), k[60], S41)
		STEP(I, D, A, B, C, GET(11), k[61], S42)
		STEP(I, C, D, A, B, GET( 2), k[62], S43)
		STEP(I, B, C, D, A, GET( 9), k[63], S44)
		
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
	MD5_u32plus saved_lo;
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

char *readfile(char *path)
{
    char *message;
    char *tmp;
    char buf[READ_FILE_SIZE + 1];
    int ret;
    int fd;

    message = ft_strnew(1);
    fd = open(path, O_RDONLY);
    while ((ret = read(fd, buf, READ_BUF_SIZE)) > 0)
    {
        buf[ret] = '\0';
        tmp = ft_strjoin(message, buf);
        free(message);
        message = tmp;
    }
    if (ret == -1)
        return (NULL);
    close(fd);
    return (message);
}

void MD5_print(t_container container, unsigned char digest[])
{
    if (!(container.flags & FLG_Q) && !(container.flags & FLG_R) && !(container.message->content_size & P_APPEND)) {
        if (container.message->content_size & IS_STR) {
            ft_putstr("MD5 (\"");
            ft_putstr(container.message->content);
            ft_putstr("\") = ");
        }
        else if (container.message->content_size & IS_FILE) {
            ft_putstr("MD5 (");
            ft_putstr(container.message->content);
            ft_putstr(") = ");
        }
    }
    if ((container.flags & FLG_P) && (container.message->content_size & P_APPEND))
        ft_putstr(container.message->content);
    for (int i = 0; i < 16; i++) {
        if (digest[i] < 0xF)
            ft_putchar('0');       
        ft_putstr(ft_itoa_base(digest[i], 16));
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
    MD5_print(container, digest);
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