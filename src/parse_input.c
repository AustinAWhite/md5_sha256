#include "../inc/ssl.h"

static void append_message(t_list **list, char *message, unsigned int type)
{
    t_list *new_message;

    new_message = ft_lstnew(message, ft_strlen(message));
    new_message->content_size = type;
    ft_lstappend(list, new_message);
}

static int set_flags(t_container *contain, char *arg, char *next)
{
    int i;
    int found;
    char *str;

    i = 0;
    while (arg[++i]) {
        if ((found = ft_chrindex(FLAGSTR, arg[i])) != -1)
            contain->flags |= flag_list[found];
        else {
            invalid_flag(contain->hash_alg, arg[i], contain->flags);
            return (1);
        }
        if (contain->flags & FLG_S) {
            contain->flags |= FLG_S;
            str = ft_isprint(arg[i + 1]) ? (arg + i + 1) : (next);
            str ? NULL : arg_required(contain->hash_alg, arg[i]);
            append_message(&contain->message, str, IS_STR);
            break ;
        }
    }
    return (0);
}

t_container parse_input(int ac, char **av)
{
    int j;
    int i;
    t_container container;

    i = 1;
    container = (t_container){NULL, 0, NULL};
    av[1] ? NULL : no_algotithm();
    for (j = 0; dispatch_lookup[j]; j++)
        if (ft_strequ(dispatch_lookup[j], av[1]))
            container.hash_alg = av[1];
    container.hash_alg && av[1] ? NULL : invalid_alg(av[1]);
    while (av[++i] && av[i][0] == '-' && !(container.flags & FLG_S)) {
        if (ft_strequ(av[i], "--")) {
            i++;
            break ;
        }
        else if (set_flags(&container, av[i], av[i + 1]))
            return (container);
    }
    if (container.message && ft_strequ(av[i], container.message->content))
        i++;
    while (i < ac)
        append_message(&container.message, av[i++], IS_FILE);
    return (container);
}