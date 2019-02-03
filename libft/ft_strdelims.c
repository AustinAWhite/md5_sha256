/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdelims.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/18 17:26:57 by awhite            #+#    #+#             */
/*   Updated: 2019/01/18 17:27:19 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int	ft_strdelims(char *str, char *delims)
{
	int i;
	int j;

	i = -1;
	while (str[++i])
	{
		j = -1;
		while (delims[++j])
			if (str[i] == delims[j])
				return (i);
	}
	return (-1);
}
