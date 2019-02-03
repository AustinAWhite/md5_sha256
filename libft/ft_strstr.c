/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:31:58 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 14:07:31 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	check_word(const char *hay, const char *ned)
{
	int i;

	i = 0;
	while (ned[i])
	{
		if (ned[i] != hay[i])
			return (0);
		i++;
	}
	return (1);
}

char		*ft_strstr(const char *haystack, const char *needle)
{
	if (!*needle)
		return ((char *)haystack);
	while (*haystack)
	{
		if (*haystack == *needle)
			if (check_word(haystack, needle))
				return ((char *)haystack);
		haystack++;
	}
	return (NULL);
}
