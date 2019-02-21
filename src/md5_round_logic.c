#include "../inc/ssl.h"
#include "../inc/md5.h"

#define LEFT_ROT(x, c)(x << c) | (x >> (32-c))

#define F(x, y, z)		((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)		((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)		(((x) ^ (y)) ^ (z))
#define H2(x, y, z)		((x) ^ ((y) ^ (z)))
#define I(x, y, z)		((y) ^ ((x) | ~(z)))

#define SET(n) (*(u_int32_t *)&ptr[(n) * 4])
#define GET(n) SET(n)

void        round1_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
    u_int32_t R;
    u_int32_t g;

    R = F((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + SET(x);
    buf[0] = buf[3];
    buf[3] = buf[2];
    buf[2] = buf[1];
    buf[1] += LEFT_ROT(R, s);
}

void        round2_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
    u_int32_t R;
    u_int32_t g;

    R = G((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
    buf[0] = buf[3];
    buf[3] = buf[2];
    buf[2] = buf[1];
    buf[1] += LEFT_ROT(R, s);
}

void        round3_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
    u_int32_t R;
    u_int32_t g;

    R = H((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
    buf[0] = buf[3];
    buf[3] = buf[2];
    buf[2] = buf[1];
    buf[1] += LEFT_ROT(R, s);
}

void        round3_logic_H2(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
    u_int32_t R;
    u_int32_t g;

    R = H2((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
    buf[0] = buf[3];
    buf[3] = buf[2];
    buf[2] = buf[1];
    buf[1] += LEFT_ROT(R, s);
}

void        round4_logic(u_int32_t *buf, u_int32_t x, u_int32_t t, u_int32_t s)
{
    u_int32_t R;
    u_int32_t g;

    R = I((buf[1]), (buf[2]), (buf[3])) + buf[0] + t + GET(x);
    buf[0] = buf[3];
    buf[3] = buf[2];
    buf[2] = buf[1];
    buf[1] += LEFT_ROT(R, s);
}