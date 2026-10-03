/* Test-only launcher for the kernel guard installed by systemd in production. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define PR_SET_AOS_NO_SETID 82
#define PR_GET_AOS_NO_SETID 83

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
        int guard = prctl(PR_GET_AOS_NO_SETID, 0UL, 0UL, 0UL, 0UL);
        if (guard == 0 || guard == 1)
            return 0;
        if (guard < 0 && errno == EINVAL)
            return 77;
        perror("query AOS no-set-ID guard");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "expected executable path\n");
        return 1;
    }
    if (prctl(PR_SET_AOS_NO_SETID, 1UL, 0UL, 0UL, 0UL) < 0 ||
        prctl(PR_GET_AOS_NO_SETID, 0UL, 0UL, 0UL, 0UL) != 1) {
        perror("install AOS no-set-ID guard");
        return 1;
    }

    execv(argv[1], &argv[1]);
    perror("exec guarded worker");
    return 1;
}
