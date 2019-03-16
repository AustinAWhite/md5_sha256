#include "../inc/ssl.h"
#include "../inc/dispatch.h"

void	dispatcher(char *input, int cmd_idx, u_int8_t type)
{
	struct stat fstat;

	if (type & IS_STR)
		g_dispatch_funcs[cmd_idx](input, cmd_idx, type);
	else if (type & IS_FILE)
	{
		if (access(input, F_OK) != -1)
		{
			stat(input, &fstat);
			if (S_ISDIR(fstat.st_mode))
				file_error(g_dispatch_lookup[cmd_idx], input,
										"Is a directory");
			else
				g_dispatch_funcs[cmd_idx](input, cmd_idx, type);
		}
		else
			file_error(g_dispatch_lookup[cmd_idx], input,
										"No such file or directory");
	}
}
