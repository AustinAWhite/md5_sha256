#include "../inc/ssl.h"
#include "../inc/dispatch.h"

static unsigned int g_flag_list[] = {
	FLG_P, FLG_Q, FLG_R, FLG_S,
};

void (*g_dispatch_funcs[])(char *input, u_int8_t type) = {
	&md5,
	&sha256,
};

const char	*g_dispatch_lookup[] = {
	"md5",
	"sha256",
	(char *)NULL,
};

char	*read_stdin(void)
{
	int		ret;
	char	buf[READ_BUF_SIZE + 1];
	char	*message;
	char	*tmp;

	message = ft_strnew(1);
	while ((ret = read(0, &buf, READ_BUF_SIZE)))
	{
		buf[ret] = '\0';
		tmp = ft_strjoin(message, buf);
		free(message);
		message = tmp;
	}
	return (message);
}

int		handle_opts(t_container *d, char *arg, char *next_arg, int *argi)
{
	int			i;
	int			found;
	char		*str;
	static int	toggle = 1;

	i = 0;
	while (arg[++i])
	{
		((found = ft_chrindex(ALL_FLAGS, arg[i])) != -1) ?
			(*d).flags |= g_flag_list[found] : invalid_flag(arg[i]);
		if (toggle && (*d).flags & FLG_P)
		{
			toggle = 0;
			dispatcher(read_stdin(), (*d).cmd_idx, (*d).flags | IS_STR | P_APPEND);
		}
		if ((*d).flags & FLG_S)
		{
			str = arg[i + i] ? &arg[i + 1] : next_arg;
			*argi += arg[i + 1] ? 1 : 2;
			str ? NULL : arg_required('s');
			dispatcher(str, (*d).cmd_idx, (*d).flags | IS_STR);
			return (1);
		}
	}
	return (0);
}

int		main(int ac, char **av)
{
	t_container	d;
	int			i;
	int			do_stdin;

	d = (t_container){-1, 0};
	i = 1;
	do_stdin = 1;
	ac == 1 ? print_usage() : NULL;
	while (g_dispatch_lookup[++d.cmd_idx] && d.cmd_idx < count_commands())
		if (ft_strequ(av[i], g_dispatch_lookup[d.cmd_idx]))
			break ;
	g_dispatch_lookup[d.cmd_idx] ? NULL : error_cmd(av[i]);
	while (av[++i] && av[i][0] == '-' && !ft_strequ(av[i], "--"))
		if (handle_opts(&d, av[i], av[i + 1], &i))
			break ;
	i += ft_strequ(av[i], "--") ? 1 : 0;
	while (av[i])
	{
		do_stdin = 0;
		dispatcher(av[i++], d.cmd_idx, d.flags | IS_FILE);
	}
	if (do_stdin && !(d.flags & FLG_P) && !(d.flags & FLG_S))
		dispatcher(read_stdin(), d.cmd_idx, d.flags | IS_STR | P_APPEND);
	return (0);
}
