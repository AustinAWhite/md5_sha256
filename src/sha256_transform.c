/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   sha256_transform.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/22 23:46:18 by awhite            #+#    #+#             */
/*   Updated: 2019/02/22 23:46:30 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../inc/ssl.h"
#include "../inc/sha256.h"

void	sha_transform2_damnnorm(t_sha256_vars *v, u_int8_t *blk_cpy)
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
		(*v).s0 = SR((*v).w[i - 15], 7) ^
						SR((*v).w[i - 15], 18) ^ ((*v).w[i - 15] >> 3);
		(*v).s1 = SR((*v).w[i - 2], 17) ^
						SR((*v).w[i - 2], 19) ^ ((*v).w[i - 2] >> 10);
		(*v).w[i] = (*v).w[i - 16] + (*v).s0 + (*v).w[i - 7] + (*v).s1;
		i++;
	}
}

void	sha_transform3_damnnorm(t_sha256_vars *v, u_int32_t wb[])
{
	int i;

	i = 0;
	while (i < 64)
	{
		(*v).s1 = SR(wb[4], 6) ^ SR(wb[4], 11) ^ SR(wb[4], 25);
		(*v).ch = (wb[4] & wb[5]) ^ (~wb[4] & wb[6]);
		(*v).temp1 = wb[7] + (*v).s1 + (*v).ch + g_sha256_k[i] + (*v).w[i];
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

void	sha_transform4_damnnorm(t_sha256_ctx *ctx, u_int8_t hash[32])
{
	int i;
	int j;

	i = 0;
	j = 0;
	while (i < 8)
	{
		hash[j++] = (uint8_t)(ctx->state[i] >> 24);
		hash[j++] = (uint8_t)(ctx->state[i] >> 16);
		hash[j++] = (uint8_t)(ctx->state[i] >> 8);
		hash[j++] = (uint8_t)ctx->state[i];
		i++;
	}
}

void	sha256_transform(t_sha256_ctx *ctx, u_int8_t hash[32])
{
	int				i;
	int				j;
	t_sha256_vars	v;
	u_int32_t		wb[8];
	u_int8_t		*blk_cpy;

	while (calc_block(ctx->block, ctx))
	{
		i = -1;
		j = -1;
		blk_cpy = ctx->block;
		ft_memset(v.w, 0x00, sizeof(v.w));
		sha_transform2_damnnorm(&v, blk_cpy);
		while (++i < 8)
			wb[i] = ctx->state[i];
		sha_transform3_damnnorm(&v, wb);
		while (++j < 8)
			ctx->state[j] += wb[j];
	}
	sha_transform4_damnnorm(ctx, hash);
}
