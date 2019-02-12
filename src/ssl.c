#include "../inc/ssl.h"

void    read_stdin(t_list **message)
{
    int ret;
    char buf[READ_BUF_SIZE + 1];
    char *str;
    char *tmp;
    t_list *new_message;

    str = ft_strnew(1);
    while ((ret = read(0, &buf, READ_BUF_SIZE)))
    {
        buf[ret] = '\0';
        tmp = ft_strjoin(str, buf);
        free(str);
        str = tmp;
    }
    new_message = ft_lstnew(str, ft_strlen(str));
    new_message->content_size = IS_STR;
    ft_lstadd(message, new_message);
}

int main(int ac, char **av)
{
    int i;
    t_container contain;

    i = -1;
    contain = parse_input(ac, av);
    if (contain.message == NULL || contain.flags & FLG_P)
        read_stdin(&contain.message);
    while (g_dispatch_lookup[++i])
        if (ft_strequ(contain.hash_alg, g_dispatch_lookup[i]))
            g_dispatch_funcs[i](contain);
    return (0);
}