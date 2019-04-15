/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   dispatch.h                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/22 23:53:38 by awhite            #+#    #+#             */
/*   Updated: 2019/02/22 23:54:51 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef DISPATCH_H
# define DISPATCH_H

# include "./md5.h"
# include "./sha256.h"
# include <string.h>

extern void (*g_dispatch_funcs[])(char *input, int cmd_idx, u_int8_t type);
extern const char	*g_dispatch_lookup[];

#endif
