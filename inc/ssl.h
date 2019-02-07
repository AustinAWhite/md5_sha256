#ifndef _SSL_
#define _SSL_

#include "../libft/libft.h"
#include "./md5.h"
#include "./sha256.h"
#include "./dispatch.h"
#include <inttypes.h>
#include <stdio.h>

#define FLG_P 0x1
#define FLG_Q 0x2
#define FLG_R 0x4
#define FLG_S 0x8
#define IS_STR 0x10
#define IS_FILE 0x20
#define FLAGSTR "pqrs"
#define READ_BUF_SIZE 1024

static unsigned int flag_list[] = {
    FLG_P, FLG_Q, FLG_R, FLG_S,
};

typedef struct          s_container
{
    char                *hash_alg;
    uint8_t             flags;
    t_list              *message;
}                       t_container;

void                    invalid_alg(char *alg);
void                    no_algotithm();
void                    invalid_flag(char *hash_alg, char c);
void                    arg_required(char *hash_alg, char c);

t_container             parse_input(int ac, char **av);

#endif