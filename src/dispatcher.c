#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void dispatcher(t_container container, char *input)
{
    struct stat fstat;
    unsigned int i;

    for (i = 0; i < count_commands(); i++)
        if (ft_strequ(container.cmd, dispatch_lookup[i]))
            break;
    if (container.info & IS_STR)
        dispatch_funcs[i](container, input);
    else if (container.info & IS_FILE)
    {
        if (access(input, F_OK) != -1) 
        {
            stat(input, &fstat);
            if (S_ISDIR(fstat.st_mode))
                file_error(container.cmd, input, "Is a directory");
            else
                dispatch_funcs[i](container, input);
        }
        else
            file_error(container.cmd, input,
										"No such file or directory");
    }
}