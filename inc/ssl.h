#ifndef _SSL_
#define _SSL_

#include "../libft/libft.h"
#include "./dispatch.h"
#include <inttypes.h>

const unsigned char FLG_P = 0x1;
const unsigned char FLG_Q = 0x2;
const unsigned char FLG_R = 0x4;
const unsigned char FLG_S = 0x8;

typedef struct  s_container
{
    char        *hash_alg;
    uint8_t     flags;
    char        *plain_text;
}               t_container;

//int             md5(t_container ssl);
//int             sha256(t_container ssl);

#endif