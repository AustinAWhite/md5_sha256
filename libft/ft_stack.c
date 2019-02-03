/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_stack.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/01/23 16:03:33 by awhite            #+#    #+#             */
/*   Updated: 2019/01/23 16:03:53 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

s_StackNode		*new_node(int data)
{
	s_StackNode *new_node;

	new_node = (s_StackNode *)malloc(sizeof(s_StackNode));
	new_node->data = data;
	new_node->next = NULL;
	return (new_node);
}

int				stack_is_empty(s_StackNode *root)
{
	return (root == NULL ? 1 : 0);
}

void			stack_push(s_StackNode **root, int data)
{
	s_StackNode *node;

	node = new_node(data);
	node->next = *root;
	*root = node;
}

void			stack_pop(s_StackNode **root)
{
	s_StackNode *temp;

	if (stack_is_empty(*root))
		return ;
	temp = *root;
	*root = (*root)->next;
	free(temp);
}

int				stack_peek(s_StackNode *root)
{
	if (stack_is_empty(root))
		return (-1);
	return (root->data);
}
