#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void    read_stdin(char **message)
{
    int ret;
    char buf[READ_BUF_SIZE + 1];
    char *str;
    char *tmp;

    str = ft_strnew(1);
    while ((ret = read(0, &buf, READ_BUF_SIZE)))
    {
        buf[ret] = '\0';
        tmp = ft_strjoin(*message, buf);
        free(*message);
        *message = tmp;
    }
}

int main(int ac, char **av)
{
    char *in;
    read_stdin(&in);
    
    
    return (0);
}