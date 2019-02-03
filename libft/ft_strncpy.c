/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:30:04 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 13:30:05 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncpy(char *dst, const char *src, size_t len)
{
	char *s2;

	s2 = dst;
	while (*src && len > 0)
	{
		*dst = *src;
		dst++;
		src++;
		len--;
	}
	while (len > 0)
	{
		*dst = '\0';
		dst++;
		len--;
	}
	return (s2);
}
