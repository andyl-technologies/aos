/* SPDX-License-Identifier: Apache-2.0 */
/* Real-kernel, metadata-only fixture for the installed retained-session ABI.
 * This proves transport lifetime and VFS mapping, not current Root authority,
 * backing joins, production worker readiness, or a content-read grant. */
#define _GNU_SOURCE

#include "aos_fuse_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NATIVE_OWNER 1000U
#define MAP_BASE 100000U
#define MAP_LENGTH 65536U
/* Both read-back maps are 0 -> MAP_BASE for MAP_LENGTH IDs. FUSE replies
 * express native IDs in the initial filesystem namespace; the mount map
 * therefore projects NATIVE_OWNER to MAP_BASE + NATIVE_OWNER. */
#define MAPPED_OWNER (MAP_BASE + NATIVE_OWNER)
#define ROOT_NODE 1U
#define PRIVATE_NODE 2U
#define LEAF_NODE 3U
#define BOUND_NS UINT64_C(15000000000)

struct fixture {
    unsigned lookup;
    unsigned getattr;
    unsigned opendir;
    unsigned destroyed;
};

struct report {
    int prepared;
    int continued;
    int second_continue;
    bool fuse_retained;
    bool cancellation_retained;
    struct fixture calls;
};

static uint64_t now_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) < 0 || now.tv_sec < 0)
        return 0;
    return (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
}

/* One absolute deadline covers all EINTR/partial-record retries. */
static int transfer(int fd, void *buffer, size_t size, bool sending)
{
    uint64_t start = now_ns();
    size_t offset = 0;
    if (start == 0)
        return -1;
    while (offset < size) {
        uint64_t now = now_ns();
        if (now == 0 || now - start >= BOUND_NS) {
            errno = ETIMEDOUT;
            return -1;
        }
        int timeout = (int)((BOUND_NS - (now - start) + 999999U) / 1000000U);
        struct pollfd descriptor = {.fd = fd, .events = sending ? POLLOUT : POLLIN};
        int ready = poll(&descriptor, 1, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0 || (descriptor.revents & descriptor.events) == 0) {
            errno = ready == 0 ? ETIMEDOUT : EIO;
            return -1;
        }
        ssize_t count = sending ? write(fd, (char *)buffer + offset, size - offset)
                                : read(fd, (char *)buffer + offset, size - offset);
        if (count < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (count <= 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int wait_child(pid_t child)
{
    uint64_t start = now_ns();
    while (start != 0) {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                return 0;
            errno = ECHILD;
            return -1;
        }
        if (result < 0 && errno != EINTR)
            return -1;
        uint64_t now = now_ns();
        if (now == 0 || now - start >= BOUND_NS)
            break;
        struct timespec delay = {.tv_nsec = 10000000};
        (void)nanosleep(&delay, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

static void kill_child(pid_t child)
{
    if (child > 0) {
        /* A failed-status wait may already have reaped this child. Do not
         * signal a numeric PID that is no longer one of our children. */
        pid_t observed = waitpid(child, NULL, WNOHANG);
        if (observed == child || (observed < 0 && errno == ECHILD))
            return;
        (void)kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
        }
    }
}

static int proc_mapping(pid_t child, const char *name, const char *value)
{
    char path[128];
    int length = snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name);
    if (length < 0 || (size_t)length >= sizeof(path))
        return -1;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t written = write(fd, value, strlen(value));
    int result = written == (ssize_t)strlen(value) ? 0 : -1;
    close(fd);
    return result;
}

/* The parent installs and then reads back the actual maps; the namespace FD
 * keeps this original namespace alive after its holder exits. */
static int mapped_namespace(unsigned base)
{
    int ready[2] = {-1, -1}, release[2] = {-1, -1};
    pid_t child = -1;
    int namespace_fd = -1;
    int result = -1;
    char byte = 'R';
    if (pipe2(ready, O_NONBLOCK | O_CLOEXEC) < 0 ||
        pipe2(release, O_NONBLOCK | O_CLOEXEC) < 0)
        goto cleanup;
    child = fork();
    if (child < 0)
        goto cleanup;
    if (child == 0) {
        alarm(20);
        close(ready[0]);
        close(release[1]);
        _exit(unshare(CLONE_NEWUSER) == 0 &&
              transfer(ready[1], &byte, 1, true) == 0 &&
              transfer(release[0], &byte, 1, false) == 0 ? 0 : 1);
    }
    close(ready[1]);
    ready[1] = -1;
    close(release[0]);
    release[0] = -1;
    char mapping[64], path[128];
    int length = snprintf(mapping, sizeof(mapping), "0 %u %u\n", base, MAP_LENGTH);
    if (length < 0 || (size_t)length >= sizeof(mapping) ||
        transfer(ready[0], &byte, 1, false) < 0 || byte != 'R' ||
        proc_mapping(child, "setgroups", "deny\n") < 0 ||
        proc_mapping(child, "uid_map", mapping) < 0 ||
        proc_mapping(child, "gid_map", mapping) < 0)
        goto cleanup;
    const char *names[] = {"uid_map", "gid_map"};
    for (unsigned index = 0; index < 2; index++) {
        length = snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, names[index]);
        if (length < 0 || (size_t)length >= sizeof(path))
            goto cleanup;
        FILE *map = fopen(path, "re");
        if (map == NULL)
            goto cleanup;
        unsigned inside, outside, count;
        char extra;
        int fields = fscanf(map, "%u %u %u %c", &inside, &outside, &count, &extra);
        fclose(map);
        if (fields != 3 || inside != 0 || outside != base || count != MAP_LENGTH)
            goto cleanup;
    }
    length = snprintf(path, sizeof(path), "/proc/%ld/ns/user", (long)child);
    if (length < 0 || (size_t)length >= sizeof(path))
        goto cleanup;
    namespace_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (namespace_fd < 0 || transfer(release[1], &byte, 1, true) < 0 ||
        wait_child(child) < 0)
        goto cleanup;
    child = -1;
    result = namespace_fd;
    namespace_fd = -1;
cleanup:
    kill_child(child);
    if (namespace_fd >= 0)
        close(namespace_fd);
    for (unsigned index = 0; index < 2; index++) {
        if (ready[index] >= 0)
            close(ready[index]);
        if (release[index] >= 0)
            close(release[index]);
    }
    return result;
}

/* fdinfo observes the original mount object without a FUSE GETATTR or a
 * detached statmount claim. No open_tree clone is used anywhere. */
static unsigned long mount_id(int fd)
{
    char path[64], line[256];
    int length = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    if (length < 0 || (size_t)length >= sizeof(path))
        return 0;
    FILE *info = fopen(path, "re");
    if (info == NULL)
        return 0;
    unsigned long id = 0;
    while (fgets(line, sizeof(line), info) != NULL)
        if (sscanf(line, "mnt_id:\t%lu", &id) == 1)
            break;
    fclose(info);
    return id;
}

static int attributes(uint64_t node, struct aos_fuse_attributes *output)
{
    if (node < ROOT_NODE || node > LEAF_NODE)
        return ENOENT;
    *output = (struct aos_fuse_attributes){
        .node_id = node, .uid = NATIVE_OWNER, .gid = NATIVE_OWNER,
        .nlink = node == LEAF_NODE ? 1 : 2, .mtime_seconds = 17,
        .mtime_nanos = 19, .mode = node == PRIVATE_NODE ? 0700 : 0555,
        .kind = node == LEAF_NODE ? AOS_FUSE_KIND_FILE : AOS_FUSE_KIND_DIRECTORY};
    return 0;
}

static int lookup(void *context, uint64_t parent, const uint8_t *name,
                  uint64_t length, struct aos_fuse_attributes *output)
{
    struct fixture *fixture = context;
    fixture->lookup++;
    if (parent == ROOT_NODE && length == 7 && memcmp(name, "private", 7) == 0)
        return attributes(PRIVATE_NODE, output);
    if (parent == ROOT_NODE && length == 4 && memcmp(name, "leaf", 4) == 0)
        return attributes(LEAF_NODE, output);
    return ENOENT;
}

static int forget(void *context, uint64_t node, uint64_t count)
{
    (void)context;
    return node >= ROOT_NODE && node <= LEAF_NODE && count != 0 ? 0 : EIO;
}

static int getattr(void *context, uint64_t node, struct aos_fuse_attributes *output)
{
    struct fixture *fixture = context;
    fixture->getattr++;
    return attributes(node, output);
}

static int fixture_readlink(void *context, uint64_t node, uint8_t *target,
                            uint64_t capacity, uint64_t *length)
{
    (void)context;
    (void)node;
    (void)target;
    (void)capacity;
    (void)length;
    return EINVAL;
}

static int opendir(void *context, uint64_t node,
                   struct aos_fuse_open_responder *responder,
                   aos_fuse_reply_open_fn reply)
{
    struct fixture *fixture = context;
    fixture->opendir++;
    return node == ROOT_NODE || node == PRIVATE_NODE ? reply(responder, node) : ENOTDIR;
}

static int readdir(void *context, uint64_t node, uint64_t handle,
                   uint64_t cookie, uint64_t maximum, struct aos_fuse_directory_entry *entries,
                   uint64_t capacity, uint64_t *count, uint8_t *names,
                   uint64_t names_capacity, uint64_t *names_length)
{
    (void)context;
    (void)node;
    (void)handle;
    (void)cookie;
    (void)maximum;
    (void)entries;
    (void)capacity;
    (void)names;
    (void)names_capacity;
    *count = 0;
    *names_length = 0;
    return 0;
}

static int releasedir(void *context, uint64_t node, uint64_t handle)
{
    (void)context;
    return node == handle ? 0 : EIO;
}

static void destroy(void *context)
{
    struct fixture *fixture = context;
    fixture->destroyed++;
}

static const struct aos_fuse_core_operations operations = {
    .abi_major = AOS_FUSE_TRANSPORT_ABI_MAJOR,
    .abi_minor = AOS_FUSE_TRANSPORT_ABI_MINOR,
    .struct_size = sizeof(struct aos_fuse_core_operations),
    .attributes_size = sizeof(struct aos_fuse_attributes),
    .directory_entry_size = sizeof(struct aos_fuse_directory_entry),
    .limits_size = sizeof(struct aos_fuse_limits),
    .lookup = lookup, .forget = forget, .getattr = getattr, .readlink = fixture_readlink,
    .opendir = opendir, .readdir = readdir, .releasedir = releasedir, .destroy = destroy};

static _Noreturn void server(int fuse_fd, int cancel_fd, int command_fd, int report_fd)
{
    alarm(45);
    struct fixture fixture = {0};
    struct report report = {0};
    long page_size = sysconf(_SC_PAGESIZE);
    uint64_t now = now_ns();
    if (page_size <= 0 || now == 0)
        _exit(2);
    struct aos_fuse_preparation_v1 preparation = {
        .struct_size = sizeof(struct aos_fuse_preparation_v1),
        .abi_major = AOS_FUSE_PREPARED_SESSION_ABI_MAJOR,
        .abi_minor = AOS_FUSE_PREPARED_SESSION_ABI_MINOR,
        .deadline_boottime_ns = now + BOUND_NS,
        .limits = {
            .struct_size = sizeof(struct aos_fuse_limits),
            .abi_major = AOS_FUSE_TRANSPORT_ABI_MAJOR,
            .abi_minor = AOS_FUSE_TRANSPORT_ABI_MINOR,
            .maximum_name_bytes = 255, .maximum_symlink_bytes = 4096,
            .maximum_readdir_bytes = 65536, .maximum_readdir_entries = 128,
            .maximum_write_bytes = 65536,
            .maximum_pages = (uint32_t)((65536U + (uint64_t)page_size - 1U) /
                                        (uint64_t)page_size),
            .time_granularity_ns = 1, .request_timeout_seconds = 1}};
    struct aos_fuse_prepared_session_v1 *prepared = NULL;
    report.prepared = aos_fuse_transport_prepare_v1(fuse_fd, cancel_fd,
                                                    &preparation, &prepared);
    /* No core is attached before this checkpoint. It acknowledges the full
     * original INIT reply, not merely allocation or an incoming INIT read. */
    if (transfer(report_fd, &report.prepared, sizeof(report.prepared), true) < 0) {
        aos_fuse_transport_destroy_prepared_v1(prepared);
        _exit(2);
    }
    char command = 0;
    if (report.prepared == 0 && transfer(command_fd, &command, 1, false) == 0 &&
        command == 'C') {
        report.continued = aos_fuse_transport_continue_prepared_v1(prepared,
                                                                   &operations, &fixture);
        report.second_continue = aos_fuse_transport_continue_prepared_v1(prepared,
                                                                         &operations, &fixture);
    } else {
        report.continued = EIO;
    }
    aos_fuse_transport_destroy_prepared_v1(prepared);
    report.fuse_retained = fcntl(fuse_fd, F_GETFD) >= 0;
    report.cancellation_retained = fcntl(cancel_fd, F_GETFD) >= 0;
    report.calls = fixture;
    close(fuse_fd);
    close(cancel_fd);
    close(command_fd);
    int result = transfer(report_fd, &report, sizeof(report), true);
    close(report_fd);
    _exit(result == 0 ? 0 : 2);
}

static int client(const char *mountpoint, uid_t uid, unsigned long original_id)
{
    if (setgroups(0, NULL) < 0 || setresgid(uid, uid, uid) < 0 ||
        setresuid(uid, uid, uid) < 0 || getuid() != uid || geteuid() != uid ||
        getgid() != uid || getegid() != uid || getgroups(0, NULL) != 0)
        return -1;
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct caps[2] = {{0}, {0}};
    if (syscall(SYS_capset, &header, caps) < 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        return -1;
    int root = open(mountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0)
        return -1;
    struct stat status;
    int result = -1;
    if (mount_id(root) != original_id || fstatat(root, "leaf", &status, 0) < 0 ||
        status.st_uid != MAPPED_OWNER || status.st_gid != MAPPED_OWNER ||
        status.st_ino != LEAF_NODE || !S_ISREG(status.st_mode) ||
        (status.st_mode & 07777U) != 0555U || status.st_size != 0 ||
        status.st_mtim.tv_sec != 17 || status.st_mtim.tv_nsec != 19)
        goto cleanup;
    int private_fd = openat(root, "private", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int error = errno;
    if (private_fd >= 0)
        close(private_fd);
    if ((uid == MAPPED_OWNER && private_fd < 0) ||
        (uid != MAPPED_OWNER && (private_fd >= 0 || error != EACCES)))
        goto cleanup;
    int written = openat(root, "new", O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    error = errno;
    if (written >= 0)
        close(written);
    if (written >= 0 || error != EROFS)
        goto cleanup;
    if (faccessat(root, "leaf", X_OK, 0) == 0 || errno != EACCES)
        goto cleanup;
    result = 0;
cleanup:
    close(root);
    return result;
}

static int run_client(const char *mountpoint, uid_t uid, unsigned long original_id)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        alarm(12);
        /* Metadata clients inherit no transport, cancellation, namespace or
         * mount capability descriptors from the privileged coordinator. */
        if (close_range(3, UINT_MAX, 0) < 0)
            _exit(2);
        int result = client(mountpoint, uid, original_id);
        if (result < 0)
            perror("retained metadata client");
        _exit(result == 0 ? 0 : 1);
    }
    int result = wait_child(child);
    if (result < 0)
        kill_child(child);
    return result;
}

static int attached_flags(const char *mountpoint)
{
    FILE *info = fopen("/proc/self/mountinfo", "re");
    if (info == NULL)
        return -1;
    char line[8192], needle[128];
    int length = snprintf(needle, sizeof(needle), " %s ", mountpoint);
    int result = -1;
    if (length < 0 || (size_t)length >= sizeof(needle))
        goto cleanup;
    while (fgets(line, sizeof(line), info) != NULL) {
        char *match = strstr(line, needle);
        if (match == NULL)
            continue;
        char *options = match + strlen(needle);
        char *end = strchr(options, ' ');
        char *filesystem = strstr(options, " - fuse ");
        if (strchr(line, '\n') == NULL || end == NULL || filesystem == NULL)
            break;
        *end = '\0';
        bool ro = false, nosuid = false, nodev = false, noexec = false;
        char *state = NULL;
        for (char *option = strtok_r(options, ",", &state); option != NULL;
             option = strtok_r(NULL, ",", &state)) {
            ro |= strcmp(option, "ro") == 0;
            nosuid |= strcmp(option, "nosuid") == 0;
            nodev |= strcmp(option, "nodev") == 0;
            noexec |= strcmp(option, "noexec") == 0;
        }
        if (ro && nosuid && nodev && noexec &&
            strstr(filesystem + 1, "default_permissions") != NULL &&
            strstr(filesystem + 1, "allow_other") != NULL)
            result = 0;
        break;
    }
cleanup:
    fclose(info);
    return result;
}

static int configure(int context, unsigned command, const char *key,
                     const char *value, int auxiliary)
{
    int result = (int)syscall(SYS_fsconfig, context, command, key, value, auxiliary);
    if (result < 0) {
        int error = errno;
        fprintf(stderr, "retained fixture fsconfig command=%u key=%s errno=%d (%s)\n",
                command, key != NULL ? key : "<none>", error, strerror(error));
        errno = error;
    }
    return result;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    if (geteuid() != 0 || unshare(CLONE_NEWNS) < 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        return 1;
    char mountpoint[] = "/tmp/aos-fuse-retained-proof-XXXXXX";
    if (mkdtemp(mountpoint) == NULL)
        return 1;
    if (chmod(mountpoint, 0755) < 0) {
        (void)rmdir(mountpoint);
        return 1;
    }
    int fuse_fd = -1, context = -1, mount_fd = -1, userns = -1, remap_ns = -1;
    int cancel[2] = {-1, -1}, commands[2] = {-1, -1}, reports[2] = {-1, -1};
    pid_t child = -1;
    bool mounted = false;
    int result = 1;
    const char *stage = "namespace/device/context creation and fsconfig";
    userns = mapped_namespace(MAP_BASE);
    remap_ns = mapped_namespace(200000U);
    fuse_fd = open("/dev/fuse", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    context = (int)syscall(SYS_fsopen, "fuse", FSOPEN_CLOEXEC);
    if (userns < 0 || remap_ns < 0 || fuse_fd < 0 || context < 0 ||
        pipe2(cancel, O_NONBLOCK | O_CLOEXEC) < 0 ||
        pipe2(commands, O_NONBLOCK | O_CLOEXEC) < 0 ||
        pipe2(reports, O_NONBLOCK | O_CLOEXEC) < 0 ||
        configure(context, FSCONFIG_SET_FD, "fd", NULL, fuse_fd) < 0 ||
        configure(context, FSCONFIG_SET_STRING, "rootmode", "40000", 0) < 0 ||
        configure(context, FSCONFIG_SET_STRING, "user_id", "0", 0) < 0 ||
        configure(context, FSCONFIG_SET_STRING, "group_id", "0", 0) < 0 ||
        configure(context, FSCONFIG_SET_STRING, "max_read", "65536", 0) < 0 ||
        configure(context, FSCONFIG_SET_FLAG, "default_permissions", NULL, 0) < 0 ||
        configure(context, FSCONFIG_SET_FLAG, "allow_other", NULL, 0) < 0 ||
        configure(context, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
        goto cleanup;
    /* Fresh /dev/fuse has asynchronous INIT. Creation queues it without a
     * lookup; fsmount retains the original anonymous mount before negotiation. */
    stage = "fsmount original detached mount";
    mount_fd = (int)syscall(SYS_fsmount, context, FSMOUNT_CLOEXEC, 0U);
    if (mount_fd < 0)
        goto cleanup;
    close(context);
    context = -1;
    stage = "fdinfo original detached mount identity";
    unsigned long original_id = mount_id(mount_fd);
    if (original_id == 0)
        goto cleanup;
    stage = "fork retained-session server";
    child = fork();
    if (child < 0)
        goto cleanup;
    if (child == 0) {
        close(mount_fd);
        close(userns);
        close(remap_ns);
        close(cancel[1]);
        close(commands[1]);
        close(reports[0]);
        server(fuse_fd, cancel[0], commands[0], reports[1]);
    }
    close(cancel[0]);
    cancel[0] = -1;
    close(commands[0]);
    commands[0] = -1;
    close(reports[1]);
    reports[1] = -1;
    int prepared;
    stage = "receive complete original INIT preparation status";
    if (transfer(reports[0], &prepared, sizeof(prepared), false) < 0)
        goto cleanup;
    if (prepared != 0) {
        int error = errno;
        fprintf(stderr, "retained fixture prepare_v1 status=%d (%s)\n",
                prepared, strerror(prepared));
        errno = error;
        goto cleanup;
    }
    struct mount_attr secure = {
        .attr_set = MOUNT_ATTR_IDMAP | MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID |
                    MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        .userns_fd = (__u64)(unsigned int)userns};
    stage = "mount_setattr original IDMAP/secureattrs and fdinfo identity";
    if (syscall(SYS_mount_setattr, mount_fd, "", AT_EMPTY_PATH, &secure, sizeof(secure)) < 0 ||
        mount_id(mount_fd) != original_id)
        goto cleanup;
    /* Exact original-object denials, not a clone or an arbitrary failure. */
    struct mount_attr again = {
        .attr_set = MOUNT_ATTR_IDMAP, .userns_fd = (__u64)(unsigned int)userns};
    stage = "mount_setattr repeated original userns IDMAP requires EPERM";
    if (syscall(SYS_mount_setattr, mount_fd, "", AT_EMPTY_PATH, &again, sizeof(again)) != -1 ||
        errno != EPERM)
        goto cleanup;
    again.userns_fd = (__u64)(unsigned int)remap_ns;
    stage = "mount_setattr alternate userns remap requires EPERM and same identity";
    if (syscall(SYS_mount_setattr, mount_fd, "", AT_EMPTY_PATH, &again, sizeof(again)) != -1 ||
        errno != EPERM || mount_id(mount_fd) != original_id)
        goto cleanup;
    char command = 'C';
    stage = "continue command and move_mount original attachment";
    if (transfer(commands[1], &command, 1, true) < 0 ||
        syscall(SYS_move_mount, mount_fd, "", AT_FDCWD, mountpoint,
                MOVE_MOUNT_F_EMPTY_PATH) < 0)
        goto cleanup;
    mounted = true;
    stage = "attached identity/flags, mapped DAC clients and cancellation";
    if (mount_id(mount_fd) != original_id || attached_flags(mountpoint) < 0 ||
        run_client(mountpoint, MAPPED_OWNER, original_id) < 0 ||
        run_client(mountpoint, MAPPED_OWNER + 1U, original_id) < 0 ||
        transfer(cancel[1], &command, 1, true) < 0)
        goto cleanup;
    struct report report;
    stage = "receive terminal retained-session report and reap server";
    if (transfer(reports[0], &report, sizeof(report), false) < 0 ||
        wait_child(child) < 0)
        goto cleanup;
    child = -1;
    stage = "terminal report, borrowed descriptors and original mount identity";
    if (report.prepared != 0 || report.continued != ECANCELED ||
        report.second_continue != EINVAL || !report.fuse_retained ||
        !report.cancellation_retained || report.calls.destroyed != 1 ||
        report.calls.lookup == 0 || report.calls.getattr == 0 ||
        report.calls.opendir == 0 || fcntl(fuse_fd, F_GETFD) < 0 ||
        fcntl(userns, F_GETFD) < 0 || mount_id(mount_fd) != original_id)
        goto cleanup;
    /* Destroy closed the C duplicate, not the parent's borrowed original.
     * Close that last original OFD before claiming global disconnection. */
    close(fuse_fd);
    fuse_fd = -1;
    struct stat disconnected;
    stage = "stat disconnected original attachment requires ENOTCONN";
    int disconnected_result = stat(mountpoint, &disconnected);
    int disconnected_error = errno;
    if (disconnected_result == 0 || disconnected_error != ENOTCONN) {
        fprintf(stderr, "retained fixture disconnected stat result=%d errno=%d (%s)\n",
                disconnected_result, disconnected_error, strerror(disconnected_error));
        errno = disconnected_error;
        goto cleanup;
    }
    /* Custody and disconnection checks are complete. Drop the original mount
     * reference so it cannot make strict unmount busy. Linux consumes the FD
     * even on a close error; report failure without retrying that numeric FD. */
    stage = "close original mount reference before strict unmount";
    int mount_close_result = close(mount_fd);
    mount_fd = -1;
    if (mount_close_result < 0)
        goto cleanup;
    stage = "umount2 original attachment flags=0";
    if (umount2(mountpoint, 0) < 0)
        goto cleanup;
    mounted = false;
    puts("{\"schema_version\":\"aos.sandbox.fuse-retained-idmap-fixture/v1\","
         "\"fixture_only\":true,\"original_init_completed\":true,"
         "\"original_session_continued\":true,\"original_mount_retained\":true,"
         "\"mapped_uid_gid\":true,\"secure_mount_flags\":true,"
         "\"repeat_idmap_eperm\":true,\"remap_eperm\":true,\"mapped_dac\":true,"
         "\"read_only\":true,\"cancelled\":true,\"destroyed_once\":true,"
         "\"borrowed_fds_retained\":true,\"disconnected\":true,\"unmounted\":true}");
    result = 0;
cleanup:
    if (result != 0) {
        int error = errno;
        fprintf(stderr, "retained FUSE IDMAP fixture stage=%s errno=%d (%s)\n",
                stage, error, strerror(error));
        errno = error;
    }
    /* Cancellation is requested even on coordinator failure; killing/reaping
     * is the bounded fallback when the child cannot reach its terminal loop. */
    if (child > 0) {
        char cancel_byte = 'X';
        if (cancel[1] >= 0) {
            ssize_t written = write(cancel[1], &cancel_byte, 1);
            if (written < 0)
                perror("best-effort retained fixture cancellation");
            else if (written != 1)
                fprintf(stderr, "best-effort retained fixture cancellation: short write\n");
        }
        kill_child(child);
    }
    if (fuse_fd >= 0)
        close(fuse_fd);
    if (context >= 0)
        close(context);
    if (mounted)
        (void)umount2(mountpoint, MNT_DETACH);
    if (mount_fd >= 0)
        close(mount_fd);
    if (userns >= 0)
        close(userns);
    if (remap_ns >= 0)
        close(remap_ns);
    for (unsigned index = 0; index < 2; index++) {
        if (cancel[index] >= 0)
            close(cancel[index]);
        if (commands[index] >= 0)
            close(commands[index]);
        if (reports[index] >= 0)
            close(reports[index]);
    }
    (void)rmdir(mountpoint);
    return result;
}
