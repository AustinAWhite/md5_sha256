#include "../inc/ssl.h"

static void         set_flags(t_container *contain, char *arg, char *next)
{
    int i;
    int found;
    t_list *message;
    char *str;

    i = 0;
    while (arg[++i])
    {
        if ((found = ft_chrindex(FLAGSTR, arg[i])) != -1)
            contain->flags |= flag_list[found];
        else
            invalid_flag(contain->hash_alg, arg[i]);
        if (contain->flags & FLG_S)
        {
            contain->flags |= FLG_S;
            str = ft_isprint(arg[i + 1]) ? (arg + i + 1) : (next);
            str ? NULL : arg_required(contain->hash_alg, arg[i]);
            message = ft_lstnew(str, ft_strlen(str));
            message->content_size = IS_STR;
            ft_lstappend(&contain->message, message);
            break ;
        }
    }
}

t_container         parse_input(int ac, char **av)
{
    int j;
    int i;
    t_container contain;
    t_list *file;

    j = -1;
    i = 1;
    contain = (t_container){NULL, 0, NULL};
    av[1] ? NULL : no_algotithm();
    while (g_dispatch_lookup[++j])
        if (ft_strequ(g_dispatch_lookup[j], av[1]))
            contain.hash_alg = av[1];
    contain.hash_alg && av[1] ? NULL : invalid_alg(av[1]);
    while (av[++i] && av[i][0] == '-' && !(contain.flags & FLG_S))
        set_flags(&contain, av[i], av[i + 1]);
    if (contain.message && ft_strequ(av[i], contain.message->content))
        i++;
    for ( ; i < ac ; i++)
    {
        file = ft_lstnew(av[i], ft_strlen(av[i]));
        file->content_size = IS_FILE;
        ft_lstappend(&contain.message, file);
    }
    return (contain);
}