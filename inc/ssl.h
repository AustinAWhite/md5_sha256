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
# define P_APPEND 0x10
# define IS_STR 0x20
# define IS_FILE 0x40
# define ALL_FLAGS "pqrs"
# define READ_BUF_SIZE 4096
# define READ_FILE_SIZE 4096

void print_usage();
void file_error(const char *cmd, char *input, char *err);
void error_cmd(char *cmd);
void arg_required(char c);
void invalid_flag(char invalid);

void dispatcher(char *input, int cmd_idx, u_int8_t type);

char *readfile(char *path);
void print_hash(char* command, char *input, unsigned char hash[],
					unsigned int size, uint8_t info);
int count_commands();

#endif
