#include "../inc/ssl.h"
#include "../inc/dispatch.h"

static void print_available()
{
    int i;

    i = -1;
    ft_putendl("Available hashing algorithms:");
    while (dispatch_lookup[++i])
    {
        ft_putstr_fd("\t", STDERR_FILENO);
        ft_putendl_fd(dispatch_lookup[i], STDERR_FILENO);
    }
}

void        print_usage(char *hash_alg)
{
    int i;

    i = -1;
    while (dispatch_lookup[++i])
        if (ft_strequ(dispatch_lookup[i], hash_alg))
        {
            ft_putendl_fd(dispatch_usage[i], STDERR_FILENO);
            break ;
        }
}

void        arg_required(char *hash_alg, char c)
{
    ft_putstr_fd(hash_alg, STDERR_FILENO);
    ft_putstr_fd(": option requires an argument -- ", STDERR_FILENO);
    ft_putchar_fd(c, STDERR_FILENO);
    ft_putendl_fd("", STDERR_FILENO);
    print_usage(hash_alg);
    exit(EXIT_FAILURE);
}

void        invalid_flag(char *hash_alg, char c, uint8_t flags)
{
    ft_putstr_fd(hash_alg, STDERR_FILENO);
    ft_putstr_fd(": illegal option -- ", STDERR_FILENO);
    ft_putchar_fd(c, STDERR_FILENO);
    ft_putendl_fd("", STDERR_FILENO);
    print_usage(hash_alg);
    if (!(flags & FLG_P))
        exit(EXIT_FAILURE);
}

void        no_algotithm()
{
    ft_putendl_fd("No hashing alorithm provided", STDERR_FILENO);
    print_available();
    exit(EXIT_FAILURE);
}

void        invalid_alg(char *alg)
{
    ft_putstr_fd("Invalid hashing algorithm: ", STDERR_FILENO);
    ft_putendl_fd(alg, STDERR_FILENO);
    print_available();
    exit(EXIT_FAILURE);
}

void        file_error(char *hash_alg, char *command, char *err)
{
    ft_putstr_fd(hash_alg, STDERR_FILENO);
    ft_putstr_fd(": ", STDERR_FILENO);
    ft_putstr_fd(command, STDERR_FILENO);
    ft_putstr_fd(": ", STDERR_FILENO);
    ft_putendl_fd(err, STDERR_FILENO);
}