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

void print_hash(t_container container, unsigned char hash[], unsigned int size, char *input)
{
    if (!(container.info & FLG_Q) && !(container.info & FLG_R) && !(container.info & FROM_STDIN)) {
        if (container.info & IS_STR) {
            ft_putstr(container.cmd);
            ft_putstr(" (\"");
            ft_putstr(input);
            ft_putstr("\") = ");
        }
        else if (container.info & IS_FILE) {
            ft_putstr(container.cmd);
            ft_putstr(" (");
            ft_putstr(input);
            ft_putstr(") = ");
        }
    }
    if ((container.info & FLG_P) && (container.info & FROM_STDIN))
        ft_putstr(input);
    for (unsigned int i = 0; i < size; i++) {
        if (hash[i] <= 0xF)
            ft_putchar('0');       
        ft_putstr(ft_itoa_base(hash[i], 16));
    }
    if (container.info & FLG_R && !(container.info & FROM_STDIN) && !(container.info & FLG_Q)) {
        if (container.info & IS_STR) {
            ft_putstr(" \"");
            ft_putstr(input);
            ft_putstr("\"");
        }
        else if (container.info & IS_FILE) {
            ft_putstr(" ");
            ft_putstr(input);
        }
    }
    ft_putendl("");
}