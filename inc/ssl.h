#ifndef _SSL_
#define _SSL_

#include "../libft/libft.h"
#include "./global.h"
#include <sys/stat.h>
#include <inttypes.h>
#include <stdio.h>

#define FLG_P 0x1
#define FLG_Q 0x2
#define FLG_R 0x4
#define FLG_S 0x8
#define FROM_STDIN 0x10
#define IS_STR 0x20
#define IS_FILE 0x40
#define FLAGSTR "pqrs"
#define READ_BUF_SIZE 4096
#define READ_FILE_SIZE 4096

static unsigned int flag_list[] = {
    FLG_P, FLG_Q, FLG_R, FLG_S,
};

void            print_usage();

void            invalid_alg(char *alg);
void            no_algotithm();
void            invalid_flag(char *hash_alg, char c, uint8_t flags);
void            arg_required(char *hash_alg, char c);
void            file_error(char *hash_alg, char *command, char *err);

void            dispatcher(t_container container, char *input);

char            *readfile(char *path);
void            print_hash(t_container container, unsigned char hash[], unsigned int size, char *input);
unsigned int    count_commands();
void            move_data(u_int32_t *arr1, u_int32_t *arr2);

#endif