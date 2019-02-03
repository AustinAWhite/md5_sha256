/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:31:35 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 16:03:58 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	word_count(char const *str, char delim)
{
	int count;

	count = 0;
	if (*str && *str != delim)
		count++;
	while (*str)
	{
		if (*str == delim)
		{
			while (*str == delim)
				str += 1;
			if (*str)
				count++;
		}
		else
			str += 1;
	}
	return (count);
}

static int	word_legnth(char const *str, char c)
{
	int i;
	int len;

	i = 0;
	len = 0;
	while (str[i] == c)
		i++;
	while (str[i] && str[i] != c)
	{
		i++;
		len++;
	}
	return (len);
}

char		**ft_strsplit(char const *s, char c)
{
	int		i;
	int		j;
	int		k;
	char	**new;

	i = 0;
	j = 0;
	if (!s)
		return (NULL);
	if ((new = (char **)malloc(sizeof(*new) * word_count(s, c) + 1)) == NULL)
		return (NULL);
	while (i < word_count(s, c))
	{
		k = 0;
		if ((new[i] = ft_strnew(word_legnth(&s[j], c) + 1)) == NULL)
			return (NULL);
		while (s[j] == c)
			j++;
		while (s[j] && s[j] != c)
			new[i][k++] = s[j++];
		new[i][k] = '\0';
		i++;
	}
	new[i] = 0;
	return (new);
}
