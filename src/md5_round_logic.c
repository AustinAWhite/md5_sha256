/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5_round_logic.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/21 22:54:56 by awhite            #+#    #+#             */
/*   Updated: 2019/02/22 23:48:01 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../inc/ssl.h"
#include "../inc/md5.h"

#define LEFT_ROT(x, c)(x << c) | (x >> (32-c))

#define F(x, y, z)		((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)		((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)		(((x) ^ (y)) ^ (z))
#define H2(x, y, z)		((x) ^ ((y) ^ (z)))
#define I(x, y, z)		((y) ^ ((x) | ~(z)))

#define SET(n) (*(u_int32_t *)&g_ptr[(n) * 4])
#define GET(n) SET(n)

void	round1_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
	u_int32_t r;

	r = F((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + SET(x);
	buf[0] = buf[3];
	buf[3] = buf[2];
	buf[2] = buf[1];
	buf[1] += LEFT_ROT(r, s);
}

void	round2_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
	u_int32_t r;

	r = G((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
	buf[0] = buf[3];
	buf[3] = buf[2];
	buf[2] = buf[1];
	buf[1] += LEFT_ROT(r, s);
}

void	round3_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
	u_int32_t r;

	r = H((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
	buf[0] = buf[3];
	buf[3] = buf[2];
	buf[2] = buf[1];
	buf[1] += LEFT_ROT(r, s);
}

void	round3_logic_h2(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
	u_int32_t r;

	r = H2((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
	buf[0] = buf[3];
	buf[3] = buf[2];
	buf[2] = buf[1];
	buf[1] += LEFT_ROT(r, s);
}

void	round4_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
	u_int32_t r;

	r = I((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
	buf[0] = buf[3];
	buf[3] = buf[2];
	buf[2] = buf[1];
	buf[1] += LEFT_ROT(r, s);
}
