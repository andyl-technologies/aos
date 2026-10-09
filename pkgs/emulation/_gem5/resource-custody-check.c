/* SPDX-License-Identifier: MIT */
#include <dmtcp.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern DmtcpGetRestartEnvErr_t dmtcp_get_restart_env(const char *, char *, size_t)
    __attribute__((weak));

int
main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/state", argv[1]);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        return 1;
    }

    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    uint64_t value = 17;
    uint64_t pending_state = 5;
    if (fd < 0 || write(fd, &value, sizeof(value)) != sizeof(value) ||
        lseek(fd, 0, SEEK_SET) != 0) {
        return 1;
    }

    int status = dmtcp_checkpoint();
    if (status != DMTCP_AFTER_CHECKPOINT && status != DMTCP_AFTER_RESTART) {
        return 1;
    }
    if (read(fd, &value, sizeof(value)) != sizeof(value) || value != 17 ||
        pending_state != 5) {
        fprintf(stderr, "lost private file or memory state at reconstruction\n");
        return 1;
    }

    unsigned long command = 1;
    if (status == DMTCP_AFTER_RESTART) {
        char argument[32];
        if (dmtcp_get_restart_env("CRUCIBLE_TEST_COMMAND", argument,
            sizeof(argument)) != RESTART_ENV_SUCCESS) {
            return 1;
        }
        char *end;
        command = strtoul(argument, &end, 10);
        if (*end || command > 100) {
            return 1;
        }
        char untouched = 'z';
        if (dmtcp_get_restart_env("CRUCIBLE_TEST_COMMAND", &untouched, 0) !=
            RESTART_ENV_TOOLONG || untouched != 'z') {
            fprintf(stderr, "restart environment wrote through an empty buffer\n");
            return 1;
        }
        char multiline[32];
        if (dmtcp_get_restart_env("CRUCIBLE_TEST_LINE", multiline,
            sizeof(multiline)) != RESTART_ENV_SUCCESS ||
            strcmp(multiline, "first\nsecond") != 0) {
            fprintf(stderr, "restart environment lost an embedded newline\n");
            return 1;
        }
    }
    value += command * pending_state;
    if (lseek(fd, 0, SEEK_SET) != 0 ||
        write(fd, &value, sizeof(value)) != sizeof(value) || close(fd) != 0) {
        return 1;
    }

    length = snprintf(path, sizeof(path), "%s/result", argv[1]);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        return 1;
    }
    FILE *output = fopen(path, "w");
    if (!output) {
        return 1;
    }
    fprintf(output, "%" PRIu64 "\n", value);
    return fclose(output) != 0;
}
