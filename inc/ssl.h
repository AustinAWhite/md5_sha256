/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ssl.h                                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: awhite <marvin@42.fr>                      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/02/23 03:26:29 by awhite            #+#    #+#             */
/*   Updated: 2019/02/23 03:27:45 by awhite           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef SSL_H
# define SSL_H

# include "../libft/libft.h"
# include "./global.h"
# include <sys/stat.h>
# include <inttypes.h>
# include <stdio.h>

# define FLG_P 0x1
# define FLG_Q 0x2
# define FLG_R 0x4
# define FLG_S 0x8
# define FS 0x10
# define IS_STR 0x20
# define IS_FILE 0x40
# define ALL_FLAGS "pqrs"
# define READ_BUF_SIZE 4096
# define READ_FILE_SIZE 4096

static unsigned int g_flag_list[] = {
	FLG_P, FLG_Q, FLG_R, FLG_S,
};

void			print_usage();
void			file_error(const char *cmd, char *input, char *err);
void			error_cmd(char *cmd);
void			arg_required(char c);
void			invalid_flag(char invalid);

void			dispatcher(char *input, int cmd_idx, u_int8_t type);

char			*readfile(char *path);
void			print_hash(char *input, u_int8_t type,
						unsigned char hash[], unsigned int size);
void			print2_damnnorm(int cmd_idx, char *input, u_int8_t info);
int				count_commands();
void			move_data(u_int32_t *arr1, u_int32_t *arr2);

#endif
