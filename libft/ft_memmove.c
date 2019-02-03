/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:19:20 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 16:11:40 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	unsigned int	i;
	unsigned char	*dst2;
	unsigned char	*src2;

	i = 0;
	dst2 = (unsigned char *)dst;
	src2 = (unsigned char *)src;
	if (src2 < dst2)
	{
		while (len-- > 0)
			dst2[len] = src2[len];
	}
	else
		while (i < len)
		{
			dst2[i] = src2[i];
			i += 1;
		}
	return (dst);
}
