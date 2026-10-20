/* Resolves exact account names through the platform's ordinary NSS interface. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[1], "passwd") && strcmp(argv[1], "group"))) {
        fputs("expected account database and exact name\n", stderr);
        return 1;
    }

    size_t capacity = 16384;
    while (capacity <= 1048576) {
        char *buffer = malloc(capacity);
        if (buffer == NULL) {
            perror("allocating account lookup buffer");
            return 1;
        }

        int error;
        int present;
        uintmax_t identity = 0;
        if (!strcmp(argv[1], "passwd")) {
            struct passwd record;
            struct passwd *result = NULL;
            error = getpwnam_r(argv[2], &record, buffer, capacity, &result);
            present = result != NULL;
            if (!error && present)
                identity = (uintmax_t)record.pw_uid;
        } else {
            struct group record;
            struct group *result = NULL;
            error = getgrnam_r(argv[2], &record, buffer, capacity, &result);
            present = result != NULL;
            if (!error && present)
                identity = (uintmax_t)record.gr_gid;
        }
        free(buffer);

        if (error == ERANGE) {
            capacity *= 2;
            continue;
        }
        if (error) {
            errno = error;
            perror("resolving account name");
            return 1;
        }
        if (!present)
            return 2;
        if (printf("%ju\n", identity) < 0 || fflush(stdout) == EOF)
            return 1;
        return 0;
    }

    fputs("account record exceeds lookup bound\n", stderr);
    return 1;
}
