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

int main(int ac, char **av)
{
    char *cmd;
    int cmd_idx;
    int i;

    cmd_idx = -1;
    i = 1;
    (ac == 1) ? print_usage() : NULL;
    while (!cmd && ++cmd_idx < count_commands())
        if (ft_strequ(av[i], dispatch_lookup[cmd_idx]))
            cmd = av[i];
    printf("%s\n", cmd);
    return (0);
}