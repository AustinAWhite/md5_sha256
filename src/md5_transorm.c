#include "../inc/ssl.h"
#include "../inc/md5.h"

static void round1(const unsigned char *ptr, 
            u_int32_t *A, u_int32_t *B, u_int32_t *C, u_int32_t *D)
{
	STEP(F, *A, *B, *C, *D, SET( 0), md5_k[ 0], S11)
    STEP(F, *D, *A, *B, *C, SET( 1), md5_k[ 1], S12)
    STEP(F, *C, *D, *A, *B, SET( 2), md5_k[ 2], S13)
    STEP(F, *B, *C, *D, *A, SET( 3), md5_k[ 3], S14)
    STEP(F, *A, *B, *C, *D, SET( 4), md5_k[ 4], S11)
    STEP(F, *D, *A, *B, *C, SET( 5), md5_k[ 5], S12)
    STEP(F, *C, *D, *A, *B, SET( 6), md5_k[ 6], S13)
    STEP(F, *B, *C, *D, *A, SET( 7), md5_k[ 7], S14)
    STEP(F, *A, *B, *C, *D, SET( 8), md5_k[ 8], S11)
    STEP(F, *D, *A, *B, *C, SET( 9), md5_k[ 9], S12)
    STEP(F, *C, *D, *A, *B, SET(10), md5_k[10], S13)
    STEP(F, *B, *C, *D, *A, SET(11), md5_k[11], S14)
    STEP(F, *A, *B, *C, *D, SET(12), md5_k[12], S11)
    STEP(F, *D, *A, *B, *C, SET(13), md5_k[13], S12)
    STEP(F, *C, *D, *A, *B, SET(14), md5_k[14], S13)
    STEP(F, *B, *C, *D, *A, SET(15), md5_k[15], S14)
}

static void round2(const unsigned char *ptr, 
            u_int32_t *A, u_int32_t *B, u_int32_t *C, u_int32_t *D)
{
	STEP(G, *A, *B, *C, *D, GET( 1), md5_k[16], S21)
    STEP(G, *D, *A, *B, *C, GET( 6), md5_k[17], S22)
    STEP(G, *C, *D, *A, *B, GET(11), md5_k[18], S23)
    STEP(G, *B, *C, *D, *A, GET( 0), md5_k[19], S24)
    STEP(G, *A, *B, *C, *D, GET( 5), md5_k[20], S21)
    STEP(G, *D, *A, *B, *C, GET(10), md5_k[21], S22)
    STEP(G, *C, *D, *A, *B, GET(15), md5_k[22], S23)
    STEP(G, *B, *C, *D, *A, GET( 4), md5_k[23], S24)
    STEP(G, *A, *B, *C, *D, GET( 9), md5_k[24], S21)
    STEP(G, *D, *A, *B, *C, GET(14), md5_k[25], S22)
    STEP(G, *C, *D, *A, *B, GET( 3), md5_k[26], S23)
    STEP(G, *B, *C, *D, *A, GET( 8), md5_k[27], S24)
    STEP(G, *A, *B, *C, *D, GET(13), md5_k[28], S21)
    STEP(G, *D, *A, *B, *C, GET( 2), md5_k[29], S22)
    STEP(G, *C, *D, *A, *B, GET( 7), md5_k[30], S23)
    STEP(G, *B, *C, *D, *A, GET(12), md5_k[31], S24)	
}

static void round3(const unsigned char *ptr, 
            u_int32_t *A, u_int32_t *B, u_int32_t *C, u_int32_t *D)
{
	STEP(H , *A, *B, *C, *D, GET( 5), md5_k[32], S31)
    STEP(H2, *D, *A, *B, *C, GET( 8), md5_k[33], S32)
	STEP(H , *C, *D, *A, *B, GET(11), md5_k[34], S33)
    STEP(H2, *B, *C, *D, *A, GET(14), md5_k[35], S34)
    STEP(H , *A, *B, *C, *D, GET( 1), md5_k[36], S31)
	STEP(H2, *D, *A, *B, *C, GET( 4), md5_k[37], S32)
    STEP(H , *C, *D, *A, *B, GET( 7), md5_k[38], S33)
    STEP(H2, *B, *C, *D, *A, GET(10), md5_k[39], S34)
    STEP(H , *A, *B, *C, *D, GET(13), md5_k[40], S31)
    STEP(H2, *D, *A, *B, *C, GET( 0), md5_k[41], S32)
    STEP(H , *C, *D, *A, *B, GET( 3), md5_k[42], S33)
    STEP(H2, *B, *C, *D, *A, GET( 6), md5_k[43], S34)
    STEP(H , *A, *B, *C, *D, GET( 9), md5_k[44], S31)
    STEP(H2, *D, *A, *B, *C, GET(12), md5_k[45], S32)
    STEP(H , *C, *D, *A, *B, GET(15), md5_k[46], S33)
    STEP(H2, *B, *C, *D, *A, GET( 2), md5_k[47], S34)
}

static void round4(const unsigned char *ptr, 
            u_int32_t *A, u_int32_t *B, u_int32_t *C, u_int32_t *D)
{
	STEP(I, *A, *B, *C, *D, GET( 0), md5_k[48], S41)
    STEP(I, *D, *A, *B, *C, GET( 7), md5_k[49], S42)
    STEP(I, *C, *D, *A, *B, GET(14), md5_k[50], S43)
    STEP(I, *B, *C, *D, *A, GET( 5), md5_k[51], S44)
    STEP(I, *A, *B, *C, *D, GET(12), md5_k[52], S41)
    STEP(I, *D, *A, *B, *C, GET( 3), md5_k[53], S42)
    STEP(I, *C, *D, *A, *B, GET(10), md5_k[54], S43)
    STEP(I, *B, *C, *D, *A, GET( 1), md5_k[55], S44)
    STEP(I, *A, *B, *C, *D, GET( 8), md5_k[56], S41)
    STEP(I, *D, *A, *B, *C, GET(15), md5_k[57], S42)
    STEP(I, *C, *D, *A, *B, GET( 6), md5_k[58], S43)
    STEP(I, *B, *C, *D, *A, GET(13), md5_k[59], S44)
    STEP(I, *A, *B, *C, *D, GET( 4), md5_k[60], S41)
    STEP(I, *D, *A, *B, *C, GET(11), md5_k[61], S42)
    STEP(I, *C, *D, *A, *B, GET( 2), md5_k[62], S43)
    STEP(I, *B, *C, *D, *A, GET( 9), md5_k[63], S44)
}

const void *md5_transform(md5_ctx *ctx,
                        const void *data, unsigned long size)
{
	const unsigned char *ptr;
	u_int32_t buf[4];
	u_int32_t working_buf[4];

	ptr = (const unsigned char *)data;
	move_data(buf, ctx->state);
	while (size)
	{
		move_data(working_buf, buf);
		round1(ptr, &buf[0], &buf[1], &buf[2], &buf[3]);
		round2(ptr, &buf[0], &buf[1], &buf[2], &buf[3]);
		round3(ptr, &buf[0], &buf[1], &buf[2], &buf[3]);
		round4(ptr, &buf[0], &buf[1], &buf[2], &buf[3]);
        buf[0] += working_buf[0];
		buf[1] += working_buf[1];
		buf[2] += working_buf[2];
		buf[3] += working_buf[3];
		ptr += 64;
		size -= 64;
	}
	move_data(ctx->state, buf);
	return (ptr);
}