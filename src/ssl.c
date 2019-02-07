#include "../inc/ssl.h"

char *itoa_base(int value, int base)
{
    static  char rep[] = "0123456789abcdef";
    static  char buf[50];
    char    *ptr;
    int     num;

    ptr = &buf[49];
    *ptr = '\0';
    num = value;
    if (value < 0 && base == 10)
        value *= -1;
    if (value == 0)
        *--ptr = rep[value % base];
    while (value != 0)
    {
        *--ptr = rep[value % base];
        value /= base;
    }
    if (num < 0 && base == 10)
        *--ptr = '-';
    return (ptr);
}

int main(int ac, char **av)
{
    t_container contain;

    contain = parse_input(ac, av);
    printf("hash_alg: %s\n", contain.hash_alg);
    printf("flags:    %04d\n          srqp\n", ft_atoi(itoa_base(contain.flags, 2)));

    t_list *tmp = contain.message;
    while (tmp)
    {
        if (tmp->content_size & IS_STR)
            printf("string:   %s\n", tmp->content);
        if (tmp->content_size & IS_FILE)
            printf("file:     %s\n", tmp->content);
        tmp = tmp->next;
    }
    if (contain.message == NULL || contain.flags & FLG_P)
        printf("read from stdin...\n");
    return (0);
}