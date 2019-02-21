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

int handle_opts(u_int8_t *flags, int cmd_idx, char *arg, char *next_arg, int *argi)
{
    int i;
    unsigned int found;
    char *str;
    static int toggle = 1;

    i = 0;
    str = NULL;
    while (arg[++i])
    {
        ((found = ft_chrindex(ALL_FLAGS, arg[i])) != -1) ?
            *flags |= flag_list[found] : invalid_flag(arg[i]);
        if (toggle && *flags & FLG_P)
        {
            toggle = 0;
            printf("str: %s\n", read_stdin());
            //dispatcher(read_stdin(), cmd_idx, *flags | IS_STR | FROM_STDIN);
        }
        if (*flags & FLG_S)
        {
            str = arg[i + i] ? &arg[i + 1] : next_arg;
            *argi += arg[i + 1] ? 1 : 2;
            str ? NULL : arg_required('s');
            //dispatcher(str, cmd_idx, *flags | IS_STR);
            printf("str: %s\n", str);
            return (1);
        }
    }
    return (0);
}

int main(int ac, char **av)
{
    int cmd_idx;
    int i;
    u_int8_t flags;
    int do_stdin;

    cmd_idx = -1;
    i = 1;
    do_stdin = 1;
    ac == 1 ? print_usage() : NULL;
    while (dispatch_lookup[++cmd_idx]&& cmd_idx < count_commands())
        if (ft_strequ(av[i], dispatch_lookup[cmd_idx]))
            break ;
    dispatch_lookup[cmd_idx] ? NULL : error_cmd(av[i]);
    while (av[++i] && av[i][0] == '-' && !ft_strequ(av[i], "--"))
        if (handle_opts(&flags, cmd_idx, av[i], av[i + 1], &i))
            break;
    if (flags & FLG_P)
        printf("p set\n");
    if (flags & FLG_Q)
        printf("q set\n");
    if (flags & FLG_R)
        printf("r set\n");
    if (flags & FLG_S)
        printf("s set\n");
    //i += (flags & FLG_S || flags == 0) ? 0 : 1;
    while (av[i])
    {
        do_stdin = 0;
        printf("file: %s\n", av[i++]);
        //dispatcher(av[i++], cmd_idx, flags | IS_FILE);
    }
    if (do_stdin && !(flags & FLG_P) && !(flags & FLG_S))
    {
        printf("str: %s\n", read_stdin());       
        //dispatcher(read_stdin(), cmd_idx, flags | IS_STR | FROM_STDIN);
    }
    return (0);
}