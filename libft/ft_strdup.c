/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:26:16 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 13:26:17 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>

static int		ft_strlen(const char *s)
{
	int len;

	len = 0;
	while (*s)
	{
		len++;
		s++;
	}
	return (len);
}

static char		*ft_strcpy(char *dst, const char *src)
{
	char *s2;

	s2 = dst;
	while (*src)
	{
		*dst = *src;
		dst++;
		src++;
	}
	*dst = '\0';
	return (s2);
}

char			*ft_strdup(const char *s1)
{
	char	*s2;

	if ((s2 = (char *)malloc(sizeof(*s1) * ft_strlen(s1) + 1)))
		return (ft_strcpy(s2, s1));
	return (NULL);
}
