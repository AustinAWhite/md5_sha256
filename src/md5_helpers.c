/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_helpers.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/21 22:50:46 by awhite            #+#    #+#             */
/*   Updated: 2019/02/21 22:50:53 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../inc/ssl.h"
#include "../inc/md5.h"

void	md5_init_ctx(md5_ctx *ctx)
{
	ctx->state[0] = md5_a0;
	ctx->state[1] = md5_b0;
	ctx->state[2] = md5_c0;
	ctx->state[3] = md5_d0;
	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

void	md5_update_damnnorm(md5_ctx *ctx, unsigned long fucknorm[],
					unsigned long *size, const void **message)
{
	fucknorm[1] = 64 - fucknorm[0];
	if (*size < fucknorm[1])
	{
		memcpy(&ctx->buffer[fucknorm[0]], *message, *size);
		return ;
	}
	memcpy(&ctx->buffer[fucknorm[0]], *message, fucknorm[1]);
	*message = *message + fucknorm[1];
	*size -= fucknorm[1];
}
