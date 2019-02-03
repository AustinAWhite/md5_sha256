/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:31:01 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 13:48:14 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	check_word(const char *hay, const char *ned, size_t len)
{
	int i;

	i = 0;
	while (ned[i] && len > 0)
	{
		if (ned[i] != hay[i])
			break ;
		i++;
		len -= 1;
	}
	if (ned[i] == '\0')
		return (1);
	else
		return (0);
}

char		*ft_strnstr(const char *haystack, const char *needle, size_t len)
{
	if (!*needle)
		return ((char *)haystack);
	while (*haystack && len > 0)
	{
		if (*haystack == *needle)
			if (check_word(haystack, needle, len))
				return ((char *)haystack);
		haystack++;
		len--;
	}
	return (NULL);
}
