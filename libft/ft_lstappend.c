/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstappend.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/09 13:55:47 by awhite            #+#    #+#             */
/*   Updated: 2019/01/09 13:55:49 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstappend(t_list **blst, t_list *newelem)
{
	t_list	*list;

	list = *blst;
	if (list)
	{
		while (list->next)
			list = list->next;
		list->next = newelem;
	}
	else
		*blst = newelem;
}
