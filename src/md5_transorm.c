#include "../inc/ssl.h"
#include "../inc/md5.h"

static void round1(const unsigned char *ptr, u_int32_t *buf)
{
	STEP(F, buf[0], buf[1], buf[2], buf[3], SET( 0), md5_k[ 0], S11)
    STEP(F, buf[3], buf[0], buf[1], buf[2], SET( 1), md5_k[ 1], S12)
    STEP(F, buf[2], buf[3], buf[0], buf[1], SET( 2), md5_k[ 2], S13)
    STEP(F, buf[1], buf[2], buf[3], buf[0], SET( 3), md5_k[ 3], S14)
    STEP(F, buf[0], buf[1], buf[2], buf[3], SET( 4), md5_k[ 4], S11)
    STEP(F, buf[3], buf[0], buf[1], buf[2], SET( 5), md5_k[ 5], S12)
    STEP(F, buf[2], buf[3], buf[0], buf[1], SET( 6), md5_k[ 6], S13)
    STEP(F, buf[1], buf[2], buf[3], buf[0], SET( 7), md5_k[ 7], S14)
    STEP(F, buf[0], buf[1], buf[2], buf[3], SET( 8), md5_k[ 8], S11)
    STEP(F, buf[3], buf[0], buf[1], buf[2], SET( 9), md5_k[ 9], S12)
    STEP(F, buf[2], buf[3], buf[0], buf[1], SET(10), md5_k[10], S13)
    STEP(F, buf[1], buf[2], buf[3], buf[0], SET(11), md5_k[11], S14)
    STEP(F, buf[0], buf[1], buf[2], buf[3], SET(12), md5_k[12], S11)
    STEP(F, buf[3], buf[0], buf[1], buf[2], SET(13), md5_k[13], S12)
    STEP(F, buf[2], buf[3], buf[0], buf[1], SET(14), md5_k[14], S13)
    STEP(F, buf[1], buf[2], buf[3], buf[0], SET(15), md5_k[15], S14)
}

static void round2(const unsigned char *ptr, u_int32_t *buf)
{
	STEP(G, buf[0], buf[1], buf[2], buf[3], GET( 1), md5_k[16], S21)
    STEP(G, buf[3], buf[0], buf[1], buf[2], GET( 6), md5_k[17], S22)
    STEP(G, buf[2], buf[3], buf[0], buf[1], GET(11), md5_k[18], S23)
    STEP(G, buf[1], buf[2], buf[3], buf[0], GET( 0), md5_k[19], S24)
    STEP(G, buf[0], buf[1], buf[2], buf[3], GET( 5), md5_k[20], S21)
    STEP(G, buf[3], buf[0], buf[1], buf[2], GET(10), md5_k[21], S22)
    STEP(G, buf[2], buf[3], buf[0], buf[1], GET(15), md5_k[22], S23)
    STEP(G, buf[1], buf[2], buf[3], buf[0], GET( 4), md5_k[23], S24)
    STEP(G, buf[0], buf[1], buf[2], buf[3], GET( 9), md5_k[24], S21)
    STEP(G, buf[3], buf[0], buf[1], buf[2], GET(14), md5_k[25], S22)
    STEP(G, buf[2], buf[3], buf[0], buf[1], GET( 3), md5_k[26], S23)
    STEP(G, buf[1], buf[2], buf[3], buf[0], GET( 8), md5_k[27], S24)
    STEP(G, buf[0], buf[1], buf[2], buf[3], GET(13), md5_k[28], S21)
    STEP(G, buf[3], buf[0], buf[1], buf[2], GET( 2), md5_k[29], S22)
    STEP(G, buf[2], buf[3], buf[0], buf[1], GET( 7), md5_k[30], S23)
    STEP(G, buf[1], buf[2], buf[3], buf[0], GET(12), md5_k[31], S24)	
}

static void round3(const unsigned char *ptr, u_int32_t *buf)
{
	STEP(H , buf[0], buf[1], buf[2], buf[3], GET( 5), md5_k[32], S31)
    STEP(H2, buf[3], buf[0], buf[1], buf[2], GET( 8), md5_k[33], S32)
	STEP(H , buf[2], buf[3], buf[0], buf[1], GET(11), md5_k[34], S33)
    STEP(H2, buf[1], buf[2], buf[3], buf[0], GET(14), md5_k[35], S34)
    STEP(H , buf[0], buf[1], buf[2], buf[3], GET( 1), md5_k[36], S31)
	STEP(H2, buf[3], buf[0], buf[1], buf[2], GET( 4), md5_k[37], S32)
    STEP(H , buf[2], buf[3], buf[0], buf[1], GET( 7), md5_k[38], S33)
    STEP(H2, buf[1], buf[2], buf[3], buf[0], GET(10), md5_k[39], S34)
    STEP(H , buf[0], buf[1], buf[2], buf[3], GET(13), md5_k[40], S31)
    STEP(H2, buf[3], buf[0], buf[1], buf[2], GET( 0), md5_k[41], S32)
    STEP(H , buf[2], buf[3], buf[0], buf[1], GET( 3), md5_k[42], S33)
    STEP(H2, buf[1], buf[2], buf[3], buf[0], GET( 6), md5_k[43], S34)
    STEP(H , buf[0], buf[1], buf[2], buf[3], GET( 9), md5_k[44], S31)
    STEP(H2, buf[3], buf[0], buf[1], buf[2], GET(12), md5_k[45], S32)
    STEP(H , buf[2], buf[3], buf[0], buf[1], GET(15), md5_k[46], S33)
    STEP(H2, buf[1], buf[2], buf[3], buf[0], GET( 2), md5_k[47], S34)
}

static void round4(const unsigned char *ptr, u_int32_t *buf)
{
	STEP(I, buf[0], buf[1], buf[2], buf[3], GET( 0), md5_k[48], S41)
    STEP(I, buf[3], buf[0], buf[1], buf[2], GET( 7), md5_k[49], S42)
    STEP(I, buf[2], buf[3], buf[0], buf[1], GET(14), md5_k[50], S43)
    STEP(I, buf[1], buf[2], buf[3], buf[0], GET( 5), md5_k[51], S44)
    STEP(I, buf[0], buf[1], buf[2], buf[3], GET(12), md5_k[52], S41)
    STEP(I, buf[3], buf[0], buf[1], buf[2], GET( 3), md5_k[53], S42)
    STEP(I, buf[2], buf[3], buf[0], buf[1], GET(10), md5_k[54], S43)
    STEP(I, buf[1], buf[2], buf[3], buf[0], GET( 1), md5_k[55], S44)
    STEP(I, buf[0], buf[1], buf[2], buf[3], GET( 8), md5_k[56], S41)
    STEP(I, buf[3], buf[0], buf[1], buf[2], GET(15), md5_k[57], S42)
    STEP(I, buf[2], buf[3], buf[0], buf[1], GET( 6), md5_k[58], S43)
    STEP(I, buf[1], buf[2], buf[3], buf[0], GET(13), md5_k[59], S44)
    STEP(I, buf[0], buf[1], buf[2], buf[3], GET( 4), md5_k[60], S41)
    STEP(I, buf[3], buf[0], buf[1], buf[2], GET(11), md5_k[61], S42)
    STEP(I, buf[2], buf[3], buf[0], buf[1], GET( 2), md5_k[62], S43)
    STEP(I, buf[1], buf[2], buf[3], buf[0], GET( 9), md5_k[63], S44)
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
		round1(ptr, buf);
		round2(ptr, buf);
		round3(ptr, buf);
		round4(ptr, buf);
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