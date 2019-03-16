#include "../inc/ssl.h"
#include "../inc/md5.h"

const unsigned char *g_ptr;

static void	round1(u_int32_t *buf)
{
	round1_logic(buf, 0, g_md5_k[0], S11);
	round1_logic(buf, 1, g_md5_k[1], S12);
	round1_logic(buf, 2, g_md5_k[2], S13);
	round1_logic(buf, 3, g_md5_k[3], S14);
	round1_logic(buf, 4, g_md5_k[4], S11);
	round1_logic(buf, 5, g_md5_k[5], S12);
	round1_logic(buf, 6, g_md5_k[6], S13);
	round1_logic(buf, 7, g_md5_k[7], S14);
	round1_logic(buf, 8, g_md5_k[8], S11);
	round1_logic(buf, 9, g_md5_k[9], S12);
	round1_logic(buf, 10, g_md5_k[10], S13);
	round1_logic(buf, 11, g_md5_k[11], S14);
	round1_logic(buf, 12, g_md5_k[12], S11);
	round1_logic(buf, 13, g_md5_k[13], S12);
	round1_logic(buf, 14, g_md5_k[14], S13);
	round1_logic(buf, 15, g_md5_k[15], S14);
}

static void	round2(u_int32_t *buf)
{
	round2_logic(buf, 1, g_md5_k[16], S21);
	round2_logic(buf, 6, g_md5_k[17], S22);
	round2_logic(buf, 11, g_md5_k[18], S23);
	round2_logic(buf, 0, g_md5_k[19], S24);
	round2_logic(buf, 5, g_md5_k[20], S21);
	round2_logic(buf, 10, g_md5_k[21], S22);
	round2_logic(buf, 15, g_md5_k[22], S23);
	round2_logic(buf, 4, g_md5_k[23], S24);
	round2_logic(buf, 9, g_md5_k[24], S21);
	round2_logic(buf, 14, g_md5_k[25], S22);
	round2_logic(buf, 3, g_md5_k[26], S23);
	round2_logic(buf, 8, g_md5_k[27], S24);
	round2_logic(buf, 13, g_md5_k[28], S21);
	round2_logic(buf, 2, g_md5_k[29], S22);
	round2_logic(buf, 7, g_md5_k[30], S23);
	round2_logic(buf, 12, g_md5_k[31], S24);
}

static void	round3(u_int32_t *buf)
{
	round3_logic(buf, 5, g_md5_k[32], S31);
	round3_logic_h2(buf, 8, g_md5_k[33], S32);
	round3_logic(buf, 11, g_md5_k[34], S33);
	round3_logic_h2(buf, 14, g_md5_k[35], S34);
	round3_logic(buf, 1, g_md5_k[36], S31);
	round3_logic_h2(buf, 4, g_md5_k[37], S32);
	round3_logic(buf, 7, g_md5_k[38], S33);
	round3_logic_h2(buf, 10, g_md5_k[39], S34);
	round3_logic(buf, 13, g_md5_k[40], S31);
	round3_logic_h2(buf, 0, g_md5_k[41], S32);
	round3_logic(buf, 3, g_md5_k[42], S33);
	round3_logic_h2(buf, 6, g_md5_k[43], S34);
	round3_logic(buf, 9, g_md5_k[44], S31);
	round3_logic_h2(buf, 12, g_md5_k[45], S32);
	round3_logic(buf, 15, g_md5_k[46], S33);
	round3_logic_h2(buf, 2, g_md5_k[47], S34);
}

static void	round4(u_int32_t *buf)
{
	round4_logic(buf, 0, g_md5_k[48], S41);
	round4_logic(buf, 7, g_md5_k[49], S42);
	round4_logic(buf, 14, g_md5_k[50], S43);
	round4_logic(buf, 5, g_md5_k[51], S44);
	round4_logic(buf, 12, g_md5_k[52], S41);
	round4_logic(buf, 3, g_md5_k[53], S42);
	round4_logic(buf, 10, g_md5_k[54], S43);
	round4_logic(buf, 1, g_md5_k[55], S44);
	round4_logic(buf, 8, g_md5_k[56], S41);
	round4_logic(buf, 15, g_md5_k[57], S42);
	round4_logic(buf, 6, g_md5_k[58], S43);
	round4_logic(buf, 13, g_md5_k[59], S44);
	round4_logic(buf, 4, g_md5_k[60], S41);
	round4_logic(buf, 11, g_md5_k[61], S42);
	round4_logic(buf, 2, g_md5_k[62], S43);
	round4_logic(buf, 9, g_md5_k[63], S44);
}

const void	*md5_transform(t_md5_ctx *ctx,
						const void *data, unsigned long size)
{
	u_int32_t buf[4];
	u_int32_t working_buf[4];

	g_ptr = (const unsigned char *)data;
	move_data(buf, ctx->state);
	while (size)
	{
		move_data(working_buf, buf);
		round1(buf);
		round2(buf);
		round3(buf);
		round4(buf);
		buf[0] += working_buf[0];
		buf[1] += working_buf[1];
		buf[2] += working_buf[2];
		buf[3] += working_buf[3];
		g_ptr += 64;
		size -= 64;
	}
	move_data(ctx->state, buf);
	return (g_ptr);
}
