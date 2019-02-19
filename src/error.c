#include "../inc/ssl.h"
#include "../inc/dispatch.h"

static void print_available()
{
    int i;

    i = -1;
    while (dispatch_lookup[++i])
    {
        ft_putstr_fd("\t", STDERR_FILENO);
        ft_putendl_fd(dispatch_lookup[i], STDERR_FILENO);
    }
}

void        print_usage()
{
    ft_putstr_fd("usage: ft_ssl command", STDERR_FILENO);
    ft_putendl_fd(" [command opts] [command args]", STDERR_FILENO);
    exit(EXIT_FAILURE);
}

void        error_cmd(char *cmd)
{
    int i;

    i = -1;
    ft_putstr_fd("ft_ssl: Error: \'", STDERR_FILENO);
    ft_putstr_fd(cmd, STDERR_FILENO);
    ft_putstr_fd("\' is an invalid command.\n\n", STDERR_FILENO);
    ft_putstr_fd("Standard commands:\n\n", STDERR_FILENO);
    ft_putstr_fd("Message Digest commands:\n", STDERR_FILENO);
    while (dispatch_lookup[++i])
        ft_putendl_fd(dispatch_lookup[i], STDERR_FILENO);
    exit(EXIT_FAILURE);
}

void        file_error(const char *cmd, char *input, char *err)
{
    ft_putstr_fd(cmd, STDERR_FILENO);
    ft_putstr_fd(": ", STDERR_FILENO);
    ft_putstr_fd(input, STDERR_FILENO);
    ft_putstr_fd(": ", STDERR_FILENO);
    ft_putendl_fd(err, STDERR_FILENO);
}

void        invalid_flag(char invalid)
{
    ft_putstr_fd("ft_ssl", STDERR_FILENO);
    ft_putstr_fd(": illegal option -- ", STDERR_FILENO);
    ft_putchar_fd(invalid, STDERR_FILENO);
    ft_putendl_fd("", STDERR_FILENO);
    print_usage();
    exit(EXIT_FAILURE);
}

void        arg_required(char c)
{
    ft_putstr_fd("ft_ssl", STDERR_FILENO);
    ft_putstr_fd(": option requires an argument -- ", STDERR_FILENO);
    ft_putchar_fd(c, STDERR_FILENO);
    ft_putendl_fd("", STDERR_FILENO);
    print_usage();
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