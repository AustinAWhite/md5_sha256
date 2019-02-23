/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   global.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/22 23:55:40 by awhite            #+#    #+#             */
/*   Updated: 2019/02/22 23:55:41 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef GLOBAL_H
# define GLOBAL_H

# include <inttypes.h>

typedef struct	s_container
{
	int			cmd_idx;
	u_int8_t	flags;
}				t_container;

#endif
