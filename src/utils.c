#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void move_data(u_int32_t *arr1, u_int32_t *arr2)
{
	arr1[0] = arr2[0];
	arr1[1] = arr2[1];
	arr1[2] = arr2[2];
	arr1[3] = arr2[3];
}

unsigned int count_commands()
{
    unsigned int cnt;

    cnt = 0;
    while (dispatch_funcs[cnt])
        cnt++;
    return (cnt);
}

char *readfile(char *path)
{
    char *message;
    char *tmp;
    char buf[READ_FILE_SIZE + 1];
    int ret;
    int fd;

    message = ft_strnew(1);
    fd = open(path, O_RDONLY);
    while ((ret = read(fd, buf, READ_BUF_SIZE)) > 0) {
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
            ft_putstr(" (");
            ft_putstr(container.message->content);
            ft_putstr(") = ");
        }
    }
    if ((container.flags & FLG_P) && (container.message->content_size & P_APPEND))
        ft_putstr(container.message->content);
    for (unsigned int i = 0; i < size; i++) {
        if (hash[i] <= 0xF)
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