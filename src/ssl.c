#include "../inc/ssl.h"

void    read_stdin(t_list **message)
{
    int ret;
    char buf[READ_BUF_SIZE + 1];
    char *str;
    char *tmp;
    t_list *new_message;

    str = ft_strnew(1);
    while ((ret = read(0, &buf, READ_BUF_SIZE))) {
        buf[ret] = '\0';
        tmp = ft_strjoin(str, buf);
        free(str);
        str = tmp;
    }
    new_message = ft_lstnew(str, ft_strlen(str));
    new_message->content_size = IS_STR;
    new_message->content_size |= P_APPEND;
    ft_lstadd(message, new_message);
}

int main(int ac, char **av)
{
    int i;
    t_container container;

    i = -1;
    container = parse_input(ac, av);
    if (container.message == NULL || container.flags & FLG_P)
        read_stdin(&container.message);
    dispatcher(container);
    return (0);
}