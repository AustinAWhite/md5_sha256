/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/10/26 13:15:02 by awhite            #+#    #+#             */
/*   Updated: 2018/10/26 16:05:53 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int		get_len(int n)
{
	int len;

	len = 2;
	while (n /= 10)
		len++;
	return (len);
}

static void		get_neg(int *n, int *neg)
{
	if (*n < 0)
	{
		*n *= -1;
		*neg = 1;
	}
	else
		*neg = 0;
}

char			*ft_itoa(int n)
{
	int		ncpy;
	int		len;
	int		neg;
	char	*str;

	if (n == -2147483648)
		return (ft_strdup("-2147483648"));
	ncpy = n;
	len = get_len(n);
	get_neg(&n, &neg);
	len += neg;
	if ((str = (char *)malloc(sizeof(char) * len)) == NULL)
		return (NULL);
	str[--len] = '\0';
	while (len--)
	{
		str[len] = n % 10 + '0';
		n /= 10;
	}
	if (neg)
		str[0] = '-';
	return (str);
}
