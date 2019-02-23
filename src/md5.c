/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.c                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/21 22:47:00 by awhite            #+#    #+#             */
/*   Updated: 2019/02/22 23:47:25 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../inc/ssl.h"
#include "../inc/md5.h"

void	md5_update(t_md5_ctx *ctx, const void *message, unsigned long size)
{
	u_int32_t		cache_len;
	unsigned long	fucknorm[2];

	cache_len = ctx->count[0];
	if ((ctx->count[0] = (cache_len + size) & 0x1fffffff) < cache_len)
		ctx->count[1]++;
	ctx->count[1] += size >> 29;
	fucknorm[0] = cache_len & 0x3f;
	if (fucknorm[0])
	{
		md5_update_damnnorm(ctx, fucknorm, &size, &message);
		md5_transform(ctx, ctx->buffer, 64);
	}
	if (size >= 64)
	{
		message = md5_transform(ctx, message, size & ~(unsigned long)0x3f);
		size &= 0x3f;
	}
	memcpy(ctx->buffer, message, size);
}

void	transform_and_out_damnnorm(t_md5_ctx *ctx, unsigned char *digest)
{
	int arr[4];

	arr[0] = 0;
	arr[1] = 56;
	arr[2] = 0;
	arr[3] = 0;
	while (arr[0] < 2)
	{
		ctx->buffer[arr[1]++] = (unsigned char)(ctx->count[arr[0]]);
		ctx->buffer[arr[1]++] = (unsigned char)((ctx->count[arr[0]]) >> 8);
		ctx->buffer[arr[1]++] = (unsigned char)((ctx->count[arr[0]]) >> 16);
		ctx->buffer[arr[1]++] = (unsigned char)((ctx->count[arr[0]]) >> 24);
		arr[0]++;
	}
	md5_transform(ctx, ctx->buffer, 64);
	while (arr[2] < 4)
	{
		digest[arr[3]++] = (unsigned char)(ctx->state[arr[2]]);
		digest[arr[3]++] = (unsigned char)((ctx->state[arr[2]]) >> 8);
		digest[arr[3]++] = (unsigned char)((ctx->state[arr[2]]) >> 16);
		digest[arr[3]++] = (unsigned char)((ctx->state[arr[2]]) >> 24);
		arr[2]++;
	}
	memset(ctx, 0, sizeof(*ctx));
}

void	md5_final(unsigned char *digest, t_md5_ctx *ctx)
{
	unsigned long used;
	unsigned long available;

	used = ctx->count[0] & 0x3f;
	ctx->buffer[used++] = 0x80;
	available = 64 - used;
	if (available < 8)
	{
		memset(&ctx->buffer[used], 0, available);
		md5_transform(ctx, ctx->buffer, 64);
		used = 0;
		available = 64;
	}
	memset(&ctx->buffer[used], 0, available - 8);
	ctx->count[0] <<= 3;
	transform_and_out_damnnorm(ctx, digest);
}

void	md5(char *input, int cmd_idx, u_int8_t type)
{
	t_md5_ctx	ctx;
	u_int8_t	digest[16];
	char		*message;

	if (type & IS_STR)
		message = input;
	else if (type & IS_FILE)
		if ((message = readfile(input)) == NULL)
			return ;
	md5_init_ctx(&ctx);
	md5_update(&ctx, message, ft_strlen(message));
	md5_final(digest, &ctx);
	print2_damnnorm(cmd_idx, input, type);
	print_hash(input, type, digest, 16);
	ft_putendl("");
}
