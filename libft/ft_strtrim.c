/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:32:37 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 15:30:25 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int		is_ws(const char c)
{
	if (c == ' ' || c == '\t' || c == '\n')
		return (1);
	return (0);
}

static void		get_bounds(const char *str, int *start, int *end)
{
	while (str[*start])
	{
		if (is_ws(str[*start]))
			*start += 1;
		else
			break ;
	}
	if (*start <= *end)
	{
		while (str[*end])
		{
			if (is_ws(str[*end]))
				*end -= 1;
			else
				break ;
		}
	}
}

static char		*trim(const char *str, int start, int end)
{
	char	*trimmed;
	int		i;
	int		len;

	i = 0;
	len = ft_strlen(str);
	trimmed = (char *)malloc(sizeof(char) * (len - start - (len - end)) + 1);
	if (!trimmed)
		return (NULL);
	while (start <= end)
	{
		trimmed[i] = str[start];
		i++;
		start++;
	}
	return (trimmed);
}

char			*ft_strtrim(char const *s)
{
	char	*trimmed;
	int		start;
	int		end;

	if (!s)
		return (NULL);
	start = 0;
	end = (int)ft_strlen(s) - 1;
	get_bounds(s, &start, &end);
	if ((start == 0) && (end == (int)ft_strlen(s) - 1))
		return (ft_strdup(s));
	else if (start > end)
	{
		if ((trimmed = ft_strnew(1)) == NULL)
			return (NULL);
		return (trimmed);
	}
	else
		trimmed = trim(s, start, end);
	if (!trimmed)
		return (NULL);
	else
		return (trimmed);
}
