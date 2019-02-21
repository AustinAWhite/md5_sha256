#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void move_data(u_int32_t *arr1, u_int32_t *arr2)
{
	arr1[0] = arr2[0];
	arr1[1] = arr2[1];
	arr1[2] = arr2[2];
	arr1[3] = arr2[3];
}

int count_commands()
{
    int cnt;

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

void    print_hash(int cmd_idx, char *input, u_int8_t info, unsigned char hash[], unsigned int size)
{
    if (!(info & FLG_Q) && !(info & FLG_R) && !(info & FROM_STDIN)) {
        if (info & IS_STR) {
            ft_putstr(dispatch_lookup[cmd_idx]);
            ft_putstr(" (\"");
            ft_putstr(input);
            ft_putstr("\") = ");
        }
        else if (info & IS_FILE) {
            ft_putstr(dispatch_lookup[cmd_idx]);
            ft_putstr(" (");
            ft_putstr(input);
            ft_putstr(") = ");
        }
    }
    if (info & FLG_P && info & FROM_STDIN)
        ft_putstr(input);
    for (unsigned int i = 0; i < size; i++) {
        if (hash[i] <= 0xF)
            ft_putchar('0');       
        ft_putstr(ft_itoa_base(hash[i], 16));
    }
    if (info & FLG_R && !(info & FROM_STDIN) && !(info & FLG_Q)) {
        if (info & IS_STR) {
            ft_putstr(" \"");
            ft_putstr(input);
            ft_putstr("\"");
        }
        else if (info & IS_FILE) {
            ft_putstr(" ");
            ft_putstr(input);
        }
    }
    ft_putendl("");
}