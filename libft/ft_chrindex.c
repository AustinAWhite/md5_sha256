#include "libft.h"

int ft_chrindex(char *str, char c)
{
    int i;

    i = -1;
    while (str[++i])
        if (str[i] == c)
            return (i);
    return (-1);
}
