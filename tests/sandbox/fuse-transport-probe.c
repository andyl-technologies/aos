/* SPDX-License-Identifier: Apache-2.0 */
/* Real-kernel metadata and mount-policy qualification for the installed bridge.
 * The fixed callback fixture deliberately does no credential authorization:
 * denied directory opens must therefore be enforced by the kernel mount.
 * Run only inside the AOS test VM, as root. */
#define _GNU_SOURCE

#include <aos_fuse_transport.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define OWNER_ID 1000U
#define OTHER_ID 1001U
#define ROOT_NODE 1U
#define PUBLIC_NODE 2U
#define PRIVATE_NODE 3U
#define LINK_NODE 4U
#define PUBLIC_LEAF 5U
#define PRIVATE_LEAF 6U

struct fixture {
    int release_notifications;
    unsigned lookup;
    unsigned getattr;
    unsigned readlink;
    unsigned opendir;
    unsigned readdir;
    unsigned releasedir;
    unsigned destroyed;
};

struct server_report {
    int status;
    int original_retained;
    int cancellation_retained;
    struct fixture calls;
};

static const char *architecture(void)
{
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#else
    return "unknown";
#endif
}

static int attributes(uint64_t node, struct aos_fuse_attributes *out)
{
    if (node < ROOT_NODE || node > PRIVATE_LEAF)
        return ESTALE;
    memset(out, 0, sizeof(*out));
    out->node_id = node;
    out->uid = OWNER_ID;
    out->gid = OWNER_ID;
    out->mtime_seconds = 17;
    out->mtime_nanos = 19;
    out->kind = node <= PRIVATE_NODE ? AOS_FUSE_KIND_DIRECTORY
                : node == LINK_NODE ? AOS_FUSE_KIND_SYMLINK
                                    : AOS_FUSE_KIND_FILE;
    out->mode = node == PRIVATE_NODE ? 0700 : node <= PUBLIC_NODE ? 0555
                                               : node == LINK_NODE ? 0777
                                                                   : 0444;
    out->nlink = node <= PRIVATE_NODE ? 2 : 1;
    out->size = node == LINK_NODE ? sizeof("public/leaf") - 1U : 0;
    return 0;
}

static int lookup(void *opaque, uint64_t parent, const uint8_t *name,
                  uint64_t length, struct aos_fuse_attributes *out)
{
    struct fixture *fixture = opaque;
    fixture->lookup++;
    uint64_t node = 0;
    if (parent == ROOT_NODE) {
        if (length == 6 && memcmp(name, "public", 6) == 0)
            node = PUBLIC_NODE;
        else if (length == 7 && memcmp(name, "private", 7) == 0)
            node = PRIVATE_NODE;
        else if (length == 4 && memcmp(name, "link", 4) == 0)
            node = LINK_NODE;
    } else if (length == 4 && memcmp(name, "leaf", 4) == 0) {
        if (parent == PUBLIC_NODE)
            node = PUBLIC_LEAF;
        else if (parent == PRIVATE_NODE)
            node = PRIVATE_LEAF;
    }
    return node == 0 ? ENOENT : attributes(node, out);
}

static int forget(void *opaque, uint64_t node, uint64_t count)
{
    (void)opaque;
    return node >= ROOT_NODE && node <= PRIVATE_LEAF && count > 0 ? 0 : ESTALE;
}

static int getattr(void *opaque, uint64_t node,
                   struct aos_fuse_attributes *out)
{
    struct fixture *fixture = opaque;
    fixture->getattr++;
    return attributes(node, out);
}

static int readlink_callback(void *opaque, uint64_t node, uint8_t *target,
                             uint64_t capacity, uint64_t *length)
{
    struct fixture *fixture = opaque;
    fixture->readlink++;
    if (node != LINK_NODE || capacity < sizeof("public/leaf") - 1U)
        return EINVAL;
    memcpy(target, "public/leaf", sizeof("public/leaf") - 1U);
    *length = sizeof("public/leaf") - 1U;
    return 0;
}

static int opendir_callback(void *opaque, uint64_t node,
                            struct aos_fuse_open_responder *responder,
                            aos_fuse_reply_open_fn reply)
{
    struct fixture *fixture = opaque;
    fixture->opendir++;
    if (node < ROOT_NODE || node > PRIVATE_NODE)
        return ENOTDIR;
    /* A fixed handle suffices because this fixture has no mutable handle state. */
    return reply(responder, node);
}

static int readdir_callback(void *opaque, uint64_t node, uint64_t handle,
                            uint64_t cookie, uint64_t maximum_output,
                            struct aos_fuse_directory_entry *entries,
                            uint64_t capacity, uint64_t *count, uint8_t *names,
                            uint64_t names_capacity, uint64_t *names_length)
{
    struct fixture *fixture = opaque;
    fixture->readdir++;
    if (node < ROOT_NODE || node > PRIVATE_NODE || handle != node)
        return EBADF;
    const char *root_names[] = {".", "..", "public", "private", "link"};
    const char *child_names[] = {".", "..", "leaf"};
    const char **source = node == ROOT_NODE ? root_names : child_names;
    uint64_t total = node == ROOT_NODE ? 5U : 3U;
    if (cookie > total)
        return EINVAL;
    *count = 0;
    *names_length = 0;
    uint64_t wire_used = 0;
    for (uint64_t index = cookie; index < total; index++) {
        size_t length = strlen(source[index]);
        /* Linux fuse_dirent is 24 bytes plus name, padded to eight bytes. */
        uint64_t wire_size = (24U + (uint64_t)length + 7U) & ~UINT64_C(7);
        if (*count == capacity || wire_size > maximum_output - wire_used ||
            length > names_capacity - *names_length)
            break;
        uint64_t child = index == 0 ? node : ROOT_NODE;
        if (index >= 2)
            child = node == ROOT_NODE ? index : node + 3U;
        entries[*count] = (struct aos_fuse_directory_entry){
            .node_id = child,
            .next_cookie = index + 1U,
            .name_offset = (uint32_t)*names_length,
            .name_length = (uint16_t)length,
            .kind = child <= PRIVATE_NODE ? AOS_FUSE_KIND_DIRECTORY
                    : child == LINK_NODE ? AOS_FUSE_KIND_SYMLINK
                                         : AOS_FUSE_KIND_FILE,
        };
        memcpy(names + *names_length, source[index], length);
        *names_length += length;
        (*count)++;
        wire_used += wire_size;
    }
    return 0;
}

static int releasedir_callback(void *opaque, uint64_t node, uint64_t handle)
{
    struct fixture *fixture = opaque;
    fixture->releasedir++;
    if (node < ROOT_NODE || node > PRIVATE_NODE || handle != node)
        return EBADF;
    uint64_t one = 1;
    ssize_t written;
    do {
        written = write(fixture->release_notifications, &one, sizeof(one));
    } while (written < 0 && errno == EINTR);
    return written == (ssize_t)sizeof(one) ? 0 : AOS_FUSE_CORE_FATAL;
}

static void destroy(void *opaque)
{
    struct fixture *fixture = opaque;
    fixture->destroyed++;
}

static const struct aos_fuse_core_operations operations = {
    .abi_major = AOS_FUSE_TRANSPORT_ABI_MAJOR,
    .abi_minor = AOS_FUSE_TRANSPORT_ABI_MINOR,
    .struct_size = sizeof(struct aos_fuse_core_operations),
    .attributes_size = sizeof(struct aos_fuse_attributes),
    .directory_entry_size = sizeof(struct aos_fuse_directory_entry),
    .limits_size = sizeof(struct aos_fuse_limits),
    .lookup = lookup,
    .forget = forget,
    .getattr = getattr,
    .readlink = readlink_callback,
    .opendir = opendir_callback,
    .readdir = readdir_callback,
    .releasedir = releasedir_callback,
    .destroy = destroy,
};

static int64_t milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) < 0)
        return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int wait_child(pid_t child, int *status)
{
    int64_t start = milliseconds();
    if (start < 0)
        return -1;
    for (;;) {
        pid_t result = waitpid(child, status, WNOHANG);
        if (result == child)
            return 0;
        if (result < 0 && errno != EINTR)
            return -1;
        int64_t now = milliseconds();
        if (now < 0 || now - start >= 15000) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct timespec delay = {.tv_nsec = 10000000};
        (void)nanosleep(&delay, NULL);
    }
}

static int list_directory(int parent, const char *name)
{
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR *directory = fdopendir(fd);
    if (directory == NULL) {
        close(fd);
        return -1;
    }
    unsigned entries = 0;
    bool leaf = false;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        entries++;
        if (strcmp(entry->d_name, "leaf") == 0)
            leaf = entry->d_ino != 0 && entry->d_type == DT_REG;
        else if (strcmp(entry->d_name, ".") != 0 &&
                 strcmp(entry->d_name, "..") != 0) {
            closedir(directory);
            errno = EIO;
            return -1;
        }
        if (entries > 3) {
            closedir(directory);
            errno = EIO;
            return -1;
        }
    }
    int error = errno;
    if (closedir(directory) < 0)
        return -1;
    if (error != 0 || entries != 3 || !leaf) {
        errno = error != 0 ? error : EIO;
        return -1;
    }
    return 0;
}

static int client(const char *mountpoint, uid_t uid)
{
    if (setgroups(0, NULL) < 0 || setresgid(uid, uid, uid) < 0 ||
        setresuid(uid, uid, uid) < 0 || getuid() != uid || geteuid() != uid ||
        getgid() != uid || getegid() != uid || getgroups(0, NULL) != 0)
        return -1;
    int root = open(mountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0)
        return -1;
    int result = -1;
    struct stat status;
    if (fstatat(root, "public/leaf", &status, 0) < 0 ||
        status.st_ino != PUBLIC_LEAF || !S_ISREG(status.st_mode) ||
        (status.st_mode & 07777U) != 0444U || status.st_uid != OWNER_ID ||
        status.st_gid != OWNER_ID || status.st_mtim.tv_sec != 17 ||
        status.st_mtim.tv_nsec != 19 || list_directory(root, "public") < 0)
        goto cleanup;
    char target[32];
    ssize_t length = readlinkat(root, "link", target, sizeof(target));
    if (length != (ssize_t)(sizeof("public/leaf") - 1U) ||
        memcmp(target, "public/leaf", sizeof("public/leaf") - 1U) != 0)
        goto cleanup;
    if (uid == OWNER_ID) {
        if (list_directory(root, "private") < 0)
            goto cleanup;
    } else {
        int private_fd = openat(root, "private", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int denied = errno;
        if (private_fd >= 0) {
            close(private_fd);
            errno = EIO;
            goto cleanup;
        }
        if (denied != EACCES ||
            fstatat(root, "private/leaf", &status, 0) == 0 || errno != EACCES)
            goto cleanup;
    }
    if (fstatat(root, "missing", &status, 0) == 0 || errno != ENOENT)
        goto cleanup;
    int written = openat(root, "new", O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    int write_error = errno;
    if (written >= 0) {
        close(written);
        errno = EIO;
        goto cleanup;
    }
    if (write_error != EROFS)
        goto cleanup;
    result = 0;
cleanup:
    close(root);
    return result;
}

static int run_client(const char *mountpoint, uid_t uid, int cancellation_fd,
                      int result_fd, int release_fd)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        alarm(15);
        close(cancellation_fd);
        close(result_fd);
        close(release_fd);
        int result = client(mountpoint, uid);
        if (result != 0)
            fprintf(stderr, "client uid=%u failed: %s\n", (unsigned)uid,
                    strerror(errno));
        _exit(result == 0 ? 0 : 1);
    }
    int status;
    if (wait_child(child, &status) < 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int await_releases(int fd)
{
    int64_t start = milliseconds();
    if (start < 0)
        return -1;
    uint64_t total = 0;
    while (total < 7) {
        int64_t now = milliseconds();
        if (now < 0 || now - start >= 15000) {
            errno = ETIMEDOUT;
            return -1;
        }
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        int ready = poll(&descriptor, 1, (int)(15000 - (now - start)));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0 || (descriptor.revents & POLLIN) == 0)
            return -1;
        uint64_t count;
        ssize_t received = read(fd, &count, sizeof(count));
        if (received < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (received != (ssize_t)sizeof(count) || count > 7 - total) {
            errno = EIO;
            return -1;
        }
        total += count;
    }
    return 0;
}

/* Kernel-reported options complement the behavioral cross-UID checks. */
static int mount_options_present(const char *mountpoint)
{
    FILE *mountinfo = fopen("/proc/self/mountinfo", "re");
    if (mountinfo == NULL)
        return -1;
    char line[8192];
    char needle[128];
    int length = snprintf(needle, sizeof(needle), " %s ", mountpoint);
    int result = -1;
    if (length < 0 || (size_t)length >= sizeof(needle))
        goto cleanup;
    while (fgets(line, sizeof(line), mountinfo) != NULL) {
        if (strchr(line, '\n') == NULL)
            goto cleanup;
        char *match = strstr(line, needle);
        if (match == NULL)
            continue;
        char *options = match + strlen(needle);
        char *end = strchr(options, ' ');
        char *filesystem = strstr(options, " - fuse ");
        if (end == NULL || filesystem == NULL)
            goto cleanup;
        *end = '\0';
        bool ro = false, nosuid = false, nodev = false;
        char *state = NULL;
        for (char *option = strtok_r(options, ",", &state); option != NULL;
             option = strtok_r(NULL, ",", &state)) {
            ro |= strcmp(option, "ro") == 0;
            nosuid |= strcmp(option, "nosuid") == 0;
            nodev |= strcmp(option, "nodev") == 0;
        }
        if (ro && nosuid && nodev &&
            strstr(filesystem + 1, "default_permissions") != NULL &&
            strstr(filesystem + 1, "allow_other") != NULL)
            result = 0;
        break;
    }
cleanup:
    fclose(mountinfo);
    if (result != 0)
        errno = EIO;
    return result;
}

int main(void)
{
    alarm(60);
    signal(SIGPIPE, SIG_IGN);
    if (geteuid() != 0 || unshare(CLONE_NEWNS) < 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("private mount namespace");
        return 1;
    }
    char mountpoint[] = "/tmp/aos-fuse-transport-proof-XXXXXX";
    if (mkdtemp(mountpoint) == NULL || chmod(mountpoint, 0755) < 0)
        return 1;
    int result = 1;
    int fuse_fd = -1;
    int cancel[2] = {-1, -1};
    int reports[2] = {-1, -1};
    int release_fd = -1;
    pid_t server = -1;
    bool mounted = false;
    fuse_fd = open("/dev/fuse", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    release_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fuse_fd < 0 || release_fd < 0 ||
        pipe2(cancel, O_NONBLOCK | O_CLOEXEC) < 0 ||
        pipe2(reports, O_NONBLOCK | O_CLOEXEC) < 0)
        goto cleanup;
    char options[256];
    int length = snprintf(options, sizeof(options),
                          "fd=%d,rootmode=40000,user_id=0,group_id=0,"
                          "default_permissions,allow_other,max_read=65536", fuse_fd);
    if (length < 0 || (size_t)length >= sizeof(options) ||
        mount("aos-fuse-transport-proof", mountpoint, "fuse",
              MS_RDONLY | MS_NOSUID | MS_NODEV, options) < 0)
        goto cleanup;
    mounted = true;
    if (mount_options_present(mountpoint) < 0)
        goto cleanup;
    server = fork();
    if (server < 0)
        goto cleanup;
    if (server == 0) {
        alarm(45);
        close(cancel[1]);
        close(reports[0]);
        struct fixture fixture = {.release_notifications = release_fd};
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0)
            _exit(2);
        struct aos_fuse_limits limits = {
            .struct_size = sizeof(struct aos_fuse_limits),
            .abi_major = AOS_FUSE_TRANSPORT_ABI_MAJOR,
            .abi_minor = AOS_FUSE_TRANSPORT_ABI_MINOR,
            .maximum_name_bytes = 255,
            .maximum_symlink_bytes = 4096,
            .maximum_readdir_bytes = 65536,
            .maximum_readdir_entries = 128,
            .maximum_write_bytes = 65536,
            .maximum_pages = (uint32_t)((65536U + (uint64_t)page_size - 1U) /
                                        (uint64_t)page_size),
            .time_granularity_ns = 1,
            .request_timeout_seconds = 1,
            .entry_valid_ns = 0,
            .attribute_valid_ns = 0,
        };
        struct server_report report = {0};
        report.status = aos_fuse_transport_run(fuse_fd, cancel[0], &operations,
                                               &fixture, &limits);
        report.original_retained = fcntl(fuse_fd, F_GETFD) >= 0;
        report.cancellation_retained = fcntl(cancel[0], F_GETFD) >= 0;
        report.calls = fixture;
        close(fuse_fd);
        close(cancel[0]);
        close(release_fd);
        ssize_t written;
        do {
            written = write(reports[1], &report, sizeof(report));
        } while (written < 0 && errno == EINTR);
        close(reports[1]);
        _exit(written == (ssize_t)sizeof(report) ? 0 : 2);
    }
    close(fuse_fd);
    fuse_fd = -1;
    close(cancel[0]);
    cancel[0] = -1;
    close(reports[1]);
    reports[1] = -1;
    if (run_client(mountpoint, OTHER_ID, cancel[1], reports[0], release_fd) < 0 ||
        run_client(mountpoint, OWNER_ID, cancel[1], reports[0], release_fd) < 0)
        goto cleanup;
    struct timespec idle = {.tv_sec = 2};
    while (nanosleep(&idle, &idle) < 0) {
        if (errno != EINTR)
            goto cleanup;
    }
    if (run_client(mountpoint, OTHER_ID, cancel[1], reports[0], release_fd) < 0 ||
        await_releases(release_fd) < 0)
        goto cleanup;
    /* The callback acknowledges release before libfuse writes its reply. A
     * subsequent metadata round trip on the single-threaded connection proves
     * those replies have completed before cancellation becomes readable. */
    struct stat barrier;
    if (stat(mountpoint, &barrier) < 0 || !S_ISDIR(barrier.st_mode))
        goto cleanup;
    if (write(cancel[1], "x", 1) != 1)
        goto cleanup;
    int status;
    if (wait_child(server, &status) < 0)
        goto cleanup;
    server = -1;
    struct server_report report;
    ssize_t received = read(reports[0], &report, sizeof(report));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        received != (ssize_t)sizeof(report) || report.status != ECANCELED ||
        !report.original_retained || !report.cancellation_retained ||
        report.calls.destroyed != 1 || report.calls.lookup == 0 ||
        report.calls.getattr == 0 || report.calls.readlink < 3 ||
        report.calls.opendir != 7 || report.calls.readdir < 2 ||
        report.calls.releasedir != report.calls.opendir) {
        fprintf(stderr, "server report or teardown assertion failed\n");
        goto cleanup;
    }
    struct stat disconnected;
    if (stat(mountpoint, &disconnected) == 0 || errno != ENOTCONN)
        goto cleanup;
    if (umount2(mountpoint, 0) < 0)
        goto cleanup;
    mounted = false;
    printf("{\"schema_version\":\"aos.sandbox.fuse-transport-proof/v1\","
           "\"architecture\":\"%s\",\"metadata\":true,"
           "\"mount_flags\":true,\"cross_uid_dac\":true,"
           "\"read_only\":true,\"idle_survives\":true,"
           "\"cancelled\":true,\"borrowed_fds_retained\":true,"
           "\"destroyed_once\":true,\"disconnected\":true,"
           "\"unmounted\":true}\n", architecture());
    result = 0;
cleanup:
    if (result != 0)
        perror("FUSE transport proof");
    if (server > 0) {
        (void)kill(server, SIGKILL);
        (void)waitpid(server, NULL, 0);
    }
    if (fuse_fd >= 0)
        close(fuse_fd);
    if (release_fd >= 0)
        close(release_fd);
    for (unsigned index = 0; index < 2; index++) {
        if (cancel[index] >= 0)
            close(cancel[index]);
        if (reports[index] >= 0)
            close(reports[index]);
    }
    if (mounted)
        (void)umount2(mountpoint, MNT_DETACH);
    (void)rmdir(mountpoint);
    return result;
}
