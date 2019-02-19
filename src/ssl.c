#include "../inc/ssl.h"
#include "../inc/dispatch.h"

char    *read_stdin()
{
    int ret;
    char buf[READ_BUF_SIZE + 1];
    char *message;
    char *tmp;

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

int handle_opts(u_int8_t *flags, int cmd_idx, char *arg, char *next_arg)
{
    int i;
    unsigned int found;
    char *str;
    int toggle;

    i = 0;
    str = NULL;
    toggle = 1;
    while (arg[++i])
    {
        ((found = ft_chrindex(ALL_FLAGS, arg[i])) != -1) ?
            *flags |= flag_list[found] : invalid_flag(arg[i]);
        if (toggle && *flags & FLG_P)
        {
            toggle = 0;
            dispatch_funcs[cmd_idx](read_stdin(), cmd_idx, *flags | IS_STR | FROM_STDIN);
        }
        if (*flags & FLG_S)
        {
            str = arg[i + i] ? &arg[i + 1] : next_arg;
            str ? NULL : arg_required('s');
            dispatch_funcs[cmd_idx](str, cmd_idx, *flags | IS_STR);
            return (arg[i + 1] ? 1: 2);
        }
    }
    return (0);
}

int main(int ac, char **av)
{
    int cmd_idx;
    int i;
    u_int8_t flags;

    cmd_idx = -1;
    i = 1;
    ac == 1 ? print_usage() : NULL;
    while (dispatch_lookup[++cmd_idx]&& cmd_idx < count_commands())
        if (ft_strequ(av[i], dispatch_lookup[cmd_idx]))
            break ;
    dispatch_lookup[cmd_idx] ? NULL : error_cmd(av[i]);
    while (av[++i] && av[i][0] == '-' && !ft_strequ(av[i], "--"))
        if (i += handle_opts(&flags, cmd_idx, av[i], av[i + 1]))
            break;
    i += flags & FLG_S ? 0 : 1;
    while (av[i])
        dispatch_funcs[cmd_idx](av[i++], cmd_idx, flags | IS_FILE);
    return (0);
}