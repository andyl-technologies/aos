/* SPDX-License-Identifier: MIT */
/* Calls the actual native hook against an isolated restart-environment shim. */
#include <dmtcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DmtcpGetRestartEnvErr_t
dmtcp_get_restart_env(const char *name, char *value, size_t capacity)
{
    const char *environment = getenv(name);
    if (!environment)
        return RESTART_ENV_NOTFOUND;
    if (strlen(environment) >= capacity)
        return RESTART_ENV_TOOLONG;
    memcpy(value, environment, strlen(environment) + 1);
    return RESTART_ENV_SUCCESS;
}

int
main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    char resolved[4096];
    dmtcp_get_new_checkpoint_file_path(argv[1], resolved, sizeof(resolved));
    return puts(resolved) < 0;
}
