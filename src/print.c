#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void	print2_damnnorm(int cmd_idx, char *input, u_int8_t info)
{
	if (!(info & FLG_Q) && !(info & FLG_R) && !(info & P_APPEND))
	{
		if (info & IS_STR)
		{
			ft_putstr(g_dispatch_lookup[cmd_idx]);
			ft_putstr(" (\"");
			ft_putstr(input);
			ft_putstr("\") = ");
		}
		else if (info & IS_FILE)
		{
			ft_putstr(g_dispatch_lookup[cmd_idx]);
			ft_putstr(" (");
			ft_putstr(input);
			ft_putstr(") = ");
		}
	}
}

void	print_hash(char *input, u_int8_t info,
						unsigned char hash[], unsigned int size)
{
	unsigned int i;

	i = -1;
	if (info & FLG_P && info & P_APPEND)
		ft_putstr(input);
	while (++i < size)
	{
		if (hash[i] <= 0xF)
			ft_putchar('0');
		ft_putstr(ft_itoa_base(hash[i], 16));
	}
	if (info & FLG_R && !(info & P_APPEND) && !(info & FLG_Q))
	{
		if (info & IS_STR)
		{
			ft_putstr(" \"");
			ft_putstr(input);
			ft_putstr("\"");
		}
		else if (info & IS_FILE)
		{
			ft_putstr(" ");
			ft_putstr(input);
		}
	}
}