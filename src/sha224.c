#include "../inc/ssl.h"
#include "../inc/sha224.h"

static void	init224_buf_state(t_sha224_ctx *ctx, const void *input, size_t len)
{
	ctx->state[0] = sha224_h0;
	ctx->state[1] = sha224_h1;
	ctx->state[2] = sha224_h2;
	ctx->state[3] = sha224_h3;
	ctx->state[4] = sha224_h4;
	ctx->state[5] = sha224_h5;
	ctx->state[6] = sha224_h6;
	ctx->state[7] = sha224_h7;
	ctx->message = input;
	ctx->count[0] = len;
	ctx->count[1] = len;
	ctx->put_one = 0;
	ctx->complete = 0;
}

void		calc224_block_fucknorm2(u_int8_t buffer[], u_int32_t *len, int *i)
{
	*i = *i - 1;
	buffer[*i] = (u_int8_t)*len;
	*len >>= 8;
}

int			calc224_block_fucknorm(u_int8_t buffer[], t_sha224_ctx *ctx,
										u_int32_t *len, size_t fcknorm[])
{
	int i;

	i = 7;
	if (!ctx->put_one)
	{
		*buffer++ = 0x80;
		fcknorm[0] -= 1;
		ctx->put_one = 1;
	}
	if (fcknorm[0] >= TOTAL_LEN)
	{
		fcknorm[1] = fcknorm[0] - TOTAL_LEN;
		*len = ctx->count[1];
		ft_memset(buffer, 0x00, fcknorm[1]);
		buffer += fcknorm[1];
		buffer[7] = (u_int8_t)(*len << 3);
		*len >>= 5;
		while (i >= 0)
			calc224_block_fucknorm2(buffer, len, &i);
		ctx->complete = 1;
	}
	else
		ft_memset(buffer, 0x00, fcknorm[0]);
	return (1);
}

int			calc224_block(u_int8_t buffer[], t_sha224_ctx *ctx)
{
	size_t		fcknorm[2];
	u_int32_t	len;

	if (ctx->complete)
		return (0);
	if (ctx->count[0] >= BSIZE_224)
	{
		ft_memcpy(buffer, ctx->message, BSIZE_224);
		ctx->message += BSIZE_224;
		ctx->count[0] -= BSIZE_224;
		return (1);
	}
	ft_memcpy(buffer, ctx->message, ctx->count[0]);
	buffer += ctx->count[0];
	fcknorm[0] = BSIZE_224 - ctx->count[0];
	ctx->message += ctx->count[0];
	ctx->count[0] = 0;
	return (calc224_block_fucknorm(buffer, ctx, &len, fcknorm));
}

void		sha224(char *input, int cmd_idx, u_int8_t info)
{
	t_sha224_ctx	ctx;
	u_int8_t		hash[32];
	char			*message;
	unsigned int	len;

	if (info & IS_STR)
		message = input;
	else if (info & IS_FILE)
		if ((message = readfile(input)) == NULL)
			return ;
	len = ft_strlen(message);
	init224_buf_state(&ctx, message, len);
	sha224_transform(&ctx, hash);
	print2_damnnorm(cmd_idx, input, info);
	print_hash(input, info, hash, 28);
	ft_putendl("");
}
