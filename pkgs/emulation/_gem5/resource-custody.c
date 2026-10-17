/* SPDX-License-Identifier: MIT */
/* Rebinds already-open owned files; future opens use DMTCP_PATH_MAPPING. */
#include <dmtcp.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int
belongs_to_root(const char *path, const char *root)
{
    size_t length = strlen(root);
    return strncmp(path, root, length) == 0 &&
        (path[length] == '/' || path[length] == '\0');
}

static void
fail_custody(const char *reason)
{
    const char message[] = "invalid native resource reconstruction binding\n";
    ssize_t written = write(STDERR_FILENO, message, sizeof(message) - 1);
    (void)written;
    written = write(STDERR_FILENO, reason, strlen(reason));
    (void)written;
    _exit(125);
}

int
dmtcp_must_ckpt_file(const char *path)
{
    const char *root = getenv("CRUCIBLE_CAPTURE_RESOURCE_ROOT");
    return root && root[0] == '/' && belongs_to_root(path, root);
}

int
dmtcp_must_overwrite_file(const char *path)
{
    /* Overwrites are permitted only for this captured private resource set.
     * The reconstruction binding must point to a fresh incarnation root. */
    return dmtcp_must_ckpt_file(path);
}

void
dmtcp_get_new_file_path(const char *path, const char *cwd, char *new_path)
{
    (void)cwd;
    new_path[0] = '\0';
    const char *root = getenv("CRUCIBLE_CAPTURE_RESOURCE_ROOT");
    if (!root || !belongs_to_root(path, root)) {
        return;
    }

    /* File reconstruction runs before the process-info plugin increments its
     * restart count. The reserved restart-environment FD is the early marker. */
    if (fcntl(dmtcp_protected_environ_fd(), F_GETFD) < 0) {
        if (errno == EBADF) {
            return;
        }
        fail_custody("cannot inspect restart marker\n");
    }

    char incarnation_root[PATH_MAX];
    DmtcpGetRestartEnvErr_t result = dmtcp_get_restart_env(
        "CRUCIBLE_RESTORE_RESOURCE_ROOT", incarnation_root, sizeof(incarnation_root));
    if (result != RESTART_ENV_SUCCESS || incarnation_root[0] != '/' ||
        strcmp(root, incarnation_root) == 0 ||
        belongs_to_root(incarnation_root, root) ||
        belongs_to_root(root, incarnation_root)) {
        fail_custody("missing or invalid incarnation root\n");
    }

    char canonical_root[PATH_MAX];
    if (!realpath(incarnation_root, canonical_root) ||
        strcmp(incarnation_root, canonical_root) != 0) {
        fail_custody("incarnation root is not a canonical private path\n");
    }

    char mapping[PATH_MAX * 2];
    if (dmtcp_get_restart_env("DMTCP_PATH_MAPPING", mapping, sizeof(mapping)) !=
        RESTART_ENV_SUCCESS) {
        fail_custody("missing future-path mapping\n");
    }
    char expected_mapping[PATH_MAX * 2];
    int mapping_length = snprintf(expected_mapping, sizeof(expected_mapping),
        "%s:%s", root, incarnation_root);
    if (mapping_length < 0 || (size_t)mapping_length >= sizeof(expected_mapping) ||
        strcmp(mapping, expected_mapping) != 0) {
        fail_custody("inconsistent future-path mapping\n");
    }

    int length = snprintf(new_path, PATH_MAX, "%s%s", incarnation_root,
        path + strlen(root));
    if (length < 0 || length >= PATH_MAX) {
        fail_custody("translated file path exceeds the limit\n");
    }

    /* A textually distinct destination can still alias another resource via
     * a symlink or hard link. Reject it before DMTCP overwrites saved bytes. */
    char canonical_path[PATH_MAX];
    struct stat destination;
    if (!realpath(new_path, canonical_path) ||
        strcmp(new_path, canonical_path) != 0 ||
        lstat(new_path, &destination) != 0 ||
        !S_ISREG(destination.st_mode) || destination.st_nlink != 1) {
        fail_custody("destination is not an isolated regular file\n");
    }
}
