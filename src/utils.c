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