#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void dispatcher(t_container container, char *message)
{
    struct stat fstat;
    unsigned int i;

    for (i = 0; i < count_commands(); i++)
        if (ft_strequ(container.hash_alg, dispatch_lookup[i]))
            break;
    while (message) {
        if (message & IS_STR)
            dispatch_funcs[i](container);
        else if (message & IS_FILE) {
            if (access(message, F_OK) != -1) {
                stat(message->content, &fstat);
                if (S_ISDIR(fstat.st_mode))
                    file_error(container.hash_alg, container.message->content,
											"Is a directory");
                else
                    dispatch_funcs[i](container);
            }
            else
                file_error(container.hash_alg, container.message->content,
											"No such file or directory");
        }
        container.message = container.message->next;
    }
}