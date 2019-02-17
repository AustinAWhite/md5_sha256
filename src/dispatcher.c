#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void dispatcher(t_container container)
{
    struct stat fstat;
    unsigned int i;

    for (i = 0; i < count_commands(); i++)
        if (ft_strequ(container.hash_alg, dispatch_lookup[i]))
            break;
    while (container.message) {
        if (container.message->content_size & IS_STR)
            dispatch_funcs[i](container);
        else if (container.message->content_size & IS_FILE) {
            if (access(container.message->content, F_OK) != -1) {
                stat(container.message->content, &fstat);
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