#include "../inc/ssl.h"

char *readfile(char *path)
{
    char *message;
    char *tmp;
    char buf[READ_FILE_SIZE + 1];
    int ret;
    int fd;

    message = ft_strnew(1);
    fd = open(path, O_RDONLY);
    while ((ret = read(fd, buf, READ_BUF_SIZE)) > 0)
    {
        buf[ret] = '\0';
        tmp = ft_strjoin(message, buf);
        free(message);
        message = tmp;
    }
    if (ret == -1)
        return (NULL);
    close(fd);
    return (message);
}

void print_hash(t_container container, unsigned char hash[], unsigned int size)
{
    if (!(container.flags & FLG_Q) && !(container.flags & FLG_R) && !(container.message->content_size & P_APPEND)) {
        if (container.message->content_size & IS_STR) {
            ft_putstr(container.hash_alg);
            ft_putstr(" (\"");
            ft_putstr(container.message->content);
            ft_putstr("\") = ");
        }
        else if (container.message->content_size & IS_FILE) {
            ft_putstr(container.hash_alg);
            ft_putstr(" (\"");
            ft_putstr(container.message->content);
            ft_putstr(") = ");
        }
    }
    if ((container.flags & FLG_P) && (container.message->content_size & P_APPEND))
        ft_putstr(container.message->content);
    for (int i = 0; i < size; i++) {
        if (hash[i] < 0xF)
            ft_putchar('0');       
        ft_putstr(ft_itoa_base(hash[i], 16));
    }
    if (container.flags & FLG_R && !(container.message->content_size & P_APPEND) && !(container.flags & FLG_Q)) {
        if (container.message->content_size & IS_STR) {
            ft_putstr(" \"");
            ft_putstr(container.message->content);
            ft_putstr("\"");
        }
        else if (container.message->content_size & IS_FILE) {
            ft_putstr(" ");
            ft_putstr(container.message->content);
        }
    }
    ft_putendl("");
}