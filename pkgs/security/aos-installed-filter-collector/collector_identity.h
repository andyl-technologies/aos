/* SPDX-License-Identifier: Apache-2.0 */
/* The unchanged fixed collector-principal checks shared by its two children. */
#ifndef AOS_COLLECTOR_IDENTITY_H
#define AOS_COLLECTOR_IDENTITY_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define COLLECTOR_CONTEXT "system_u:system_r:aos_installed_filter_collector_t:s0"

static int read_text(const char *path, char *bytes, size_t capacity)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    size_t length = 0;
    while (length < capacity) {
        ssize_t count = read(fd, bytes + length, capacity - length);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            close(fd);
            return -1;
        }
        if (count == 0)
            break;
        length += (size_t)count;
    }
    close(fd);
    if (length == 0 || length == capacity)
        return -1;
    bytes[length] = '\0';
    return 0;
}

static int require_text(const char *path, const char *expected)
{
    char bytes[512];
    if (read_text(path, bytes, sizeof(bytes)) != 0)
        return -1;
    size_t length = strlen(bytes);
    if (length != 0 && bytes[length - 1] == '\n')
        bytes[--length] = '\0';
    return strcmp(bytes, expected) == 0 ? 0 : -1;
}

static int status_number(const char *status, const char *name,
    unsigned int base, uint64_t *value)
{
    const char *field = status;
    while ((field = strstr(field, name)) != NULL) {
        if (field == status || field[-1] == '\n') {
            char *end = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(field + strlen(name), &end, base);
            if (errno != 0 || end == field + strlen(name)
                || (*end != '\n' && *end != '\0'))
                return -1;
            *value = parsed;
            return 0;
        }
        ++field;
    }
    return -1;
}

static int require_collector(void)
{
    char status[8192];
    if (getuid() != 0 || geteuid() != 0 || prctl(PR_GET_SECCOMP) != 0
        || require_text("/sys/fs/selinux/enforce", "1") != 0
        || require_text("/proc/self/attr/current", COLLECTOR_CONTEXT) != 0
        || read_text("/proc/self/status", status, sizeof(status)) != 0)
        return -1;
    const uint64_t required = (UINT64_C(1) << 19) | (UINT64_C(1) << 21);
    for (size_t index = 0; index < 5; ++index) {
        static const char *fields[] = {"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"};
        uint64_t value = 0;
        uint64_t expected = index == 0 || index == 4 ? 0 : required;
        if (status_number(status, fields[index], 16, &value) != 0 || value != expected)
            return -1;
    }
    return 0;
}

#endif
