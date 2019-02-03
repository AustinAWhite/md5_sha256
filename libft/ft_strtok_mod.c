/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtok_mod.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/18 17:24:15 by awhite            #+#    #+#             */
/*   Updated: 2019/01/18 17:25:31 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	word_count(char *str, char *delims)
{
	int i;
	int ret;
	int count;

	i = -1;
	count = 0;
	while ((ret = ft_strdelims(&str[++i], delims)) != -1)
	{
		if (!ft_strchr(delims, str[i]))
			count++;
		i += ret;
	}
	if (str[i])
		count++;
	return (count);
}

static int	word_length(char *str, char *delims)
{
	int i;
	int len;

	i = 0;
	len = 0;
	while (ft_strchr(delims, str[i]))
		i++;
	while (str[i] && ft_strdelims(&str[i], delims))
	{
		i++;
		len++;
	}
	return (len);
}

char		**ft_strtok_mod(char *s, char *delims)
{
	int		i;
	int		j;
	int		k;
	char	**new;

	i = 0;
	j = 0;
	if (!s)
		return (NULL);
	if (!(new = (char **)malloc(sizeof(*new) * word_count(s, delims) + 1)))
		return (NULL);
	while (i < word_count(s, delims))
	{
		k = 0;
		if ((new[i] = ft_strnew(word_length(&s[j], delims) + 1)) == NULL)
			return (NULL);
		while (ft_strchr(delims, s[j]))
			j++;
		while (s[j] && !ft_strchr(delims, s[j]))
			new[i][k++] = s[j++];
		new[i][k] = '\0';
		i++;
	}
	new[i] = 0;
	return (new);
}
