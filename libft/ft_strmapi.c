/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:29:01 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 16:01:58 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmapi(char const *s, char (*f)(unsigned int, char))
{
	char	*new;
	int		i;

	i = 0;
	if (!s)
		return (NULL);
	if ((new = ft_strnew(ft_strlen(s))) == NULL)
		return (NULL);
	while (*(s + i))
	{
		*(new + i) = f(i, *(s + i));
		i++;
	}
	return (new);
}
