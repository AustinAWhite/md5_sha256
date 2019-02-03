/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_isalpha.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:12:44 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 13:12:54 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ft_isupper(int c)
{
	return ((c >= 'A' && c <= 'Z') ? 1 : 0);
}

static int	ft_islower(int c)
{
	return ((c >= 'a' && c <= 'z') ? 1 : 0);
}

int			ft_isalpha(int c)
{
	if (ft_isupper(c) || ft_islower(c))
		return (1);
	return (0);
}
