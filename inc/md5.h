/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   md5.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/22 23:59:55 by awhite            #+#    #+#             */
/*   Updated: 2019/02/23 00:00:04 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef MD5_H
# define MD5_H

# include <inttypes.h>

# define S11 7
# define S12 12
# define S13 17
# define S14 22
# define S21 5
# define S22 9
# define S23 14
# define S24 20
# define S31 4
# define S32 11
# define S33 16
# define S34 23
# define S41 6
# define S42 10
# define S43 15
# define S44 21

typedef struct	s_md5_ctx
{
	u_int32_t	state[4];
	u_int32_t	count[2];
	u_int8_t	buffer[64];
	u_int32_t	block[16];
}				t_md5_ctx;

extern const unsigned char *g_ptr;

extern uint32_t g_md5_k[64];

enum	e_md5_buf_init
{
	md5_a0 = (uint32_t)0x67452301,
	md5_b0 = (uint32_t)0xefcdab89,
	md5_c0 = (uint32_t)0x98badcfe,
	md5_d0 = (uint32_t)0x10325476
};

void			md5(char *input, int cmd_idx, u_int8_t type);
void			move_data(u_int32_t *arr1, u_int32_t *arr2);
const void		*md5_transform(t_md5_ctx *ctx,
								const void *data, unsigned long size);
void			md5_init_ctx(t_md5_ctx *ctx);
void			md5_update_damnnorm(t_md5_ctx *ctx,
								unsigned long fucknorm[],
								unsigned long *size, const void **message);
void			round1_logic(u_int32_t *buf, u_int32_t x,
								u_int32_t t, u_int32_t s);
void			round2_logic(u_int32_t *buf, u_int32_t x,
								u_int32_t t, u_int32_t s);
void			round3_logic(u_int32_t *buf, u_int32_t x,
								u_int32_t t, u_int32_t s);
void			round3_logic_h2(u_int32_t *buf, u_int32_t x,
								u_int32_t t, u_int32_t s);
void			round4_logic(u_int32_t *buf, u_int32_t x,
								u_int32_t t, u_int32_t s);

#endif
