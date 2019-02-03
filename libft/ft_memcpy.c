/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 14:00:05 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 14:06:58 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	size_t	i;
	char	*ptr;
	char	*ptr2;

	i = 0;
	ptr = dst;
	ptr2 = (char *)src;
	while (i < n)
	{
		ptr[i] = ptr2[i];
		i++;
	}
	return (dst);
}
