/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Architecture-neutral runtime probe for fs-verity and FUSE passthrough.
 *
 * This deliberately speaks the kernel UAPI directly.  It proves that the
 * packaged headers expose the required ABI and that the running kernel can
 * enable and measure verity and can service reads through a registered FUSE
 * backing file without sending FUSE_READ to userspace.
 * The VM-only fake-verity mode proves an unprivileged FUSE daemon can return
 * fabricated measurement bytes, then checks the Rust APIs reject that proof
 * source without issuing their own measurement ioctl.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/fs.h>
#include <linux/fsverity.h>
#include <linux/fuse.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(FS_IOC_ENABLE_VERITY) || !defined(FS_IOC_MEASURE_VERITY) ||      \
    !defined(FUSE_PASSTHROUGH) || !defined(FOPEN_PASSTHROUGH) ||             \
    !defined(FUSE_DEV_IOC_BACKING_OPEN) ||                                   \
    !defined(FUSE_DEV_IOC_BACKING_CLOSE)
#error "Linux headers do not expose the fs-verity and FUSE passthrough UAPI"
#endif

#define PROBE_FILE_NODE_ID 2U
#define PROBE_FILE_NAME "payload"
#define MAXIMUM_PROBE_FILE_BYTES 4096U
#define PROBE_MAX_WRITE (128U * 1024U)
#define FAKE_VERITY_FILE_BYTES 7U

struct server_result {
    uint64_t offered_flags;
    uint32_t read_requests;
    uint32_t protocol_minor;
    int32_t backing_id;
    int32_t error_number;
    uint32_t measurement_requests;
    uint32_t statfs_requests;
    uint32_t ordinary_open_requests;
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

static int write_message(int fd, const void *message, size_t length)
{
    ssize_t written;

    do {
        written = write(fd, message, length);
    } while (written < 0 && errno == EINTR);
    if (written < 0)
        return -1;
    if ((size_t)written != length) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int reply_error(int fuse_fd, const struct fuse_in_header *request,
                       int error_number)
{
    const struct fuse_out_header response = {
        .len = sizeof(response),
        .error = -error_number,
        .unique = request->unique,
    };

    return write_message(fuse_fd, &response, sizeof(response));
}

static void fill_attr(struct fuse_attr *attribute, const struct stat *backing,
                      bool directory)
{
    memset(attribute, 0, sizeof(*attribute));
    attribute->ino = directory ? FUSE_ROOT_ID : PROBE_FILE_NODE_ID;
    attribute->size = directory ? 0U : (uint64_t)backing->st_size;
    attribute->blocks = directory ? 0U : (uint64_t)backing->st_blocks;
    attribute->atime = (uint64_t)backing->st_atim.tv_sec;
    attribute->mtime = (uint64_t)backing->st_mtim.tv_sec;
    attribute->ctime = (uint64_t)backing->st_ctim.tv_sec;
    attribute->atimensec = (uint32_t)backing->st_atim.tv_nsec;
    attribute->mtimensec = (uint32_t)backing->st_mtim.tv_nsec;
    attribute->ctimensec = (uint32_t)backing->st_ctim.tv_nsec;
    attribute->mode = directory ? (S_IFDIR | 0555U) : (S_IFREG | 0444U);
    attribute->nlink = directory ? 2U : 1U;
    attribute->uid = 0U;
    attribute->gid = 0U;
    attribute->blksize = 4096U;
}

static int reply_init(int fuse_fd, const struct fuse_in_header *header,
                      const void *payload, size_t payload_length,
                      struct server_result *result, bool fake_verity)
{
    struct {
        struct fuse_out_header header;
        struct fuse_init_out body;
    } response;
    struct fuse_init_in decoded;
    const struct fuse_init_in *request = &decoded;
    uint64_t flags;

    if (payload_length < sizeof(*request)) {
        errno = EPROTO;
        return -1;
    }
    memcpy(&decoded, payload, sizeof(decoded));
    flags = (uint64_t)request->flags | ((uint64_t)request->flags2 << 32);
    result->offered_flags = flags;
    if (!fake_verity && (flags & FUSE_PASSTHROUGH) == 0U) {
        errno = EOPNOTSUPP;
        return -1;
    }

    memset(&response, 0, sizeof(response));
    response.header.len = sizeof(response);
    response.header.unique = header->unique;
    response.body.major = FUSE_KERNEL_VERSION;
    response.body.minor = request->minor < FUSE_KERNEL_MINOR_VERSION
                              ? request->minor
                              : FUSE_KERNEL_MINOR_VERSION;
    response.body.max_readahead = request->max_readahead;
    response.body.max_write = PROBE_MAX_WRITE;
    response.body.flags = FUSE_INIT_EXT;
    response.body.flags2 = fake_verity ? 0U : (uint32_t)(FUSE_PASSTHROUGH >> 32);
    response.body.max_stack_depth = fake_verity ? 0U : 1U;
    result->protocol_minor = response.body.minor;
    return write_message(fuse_fd, &response, sizeof(response));
}

static int reply_lookup(int fuse_fd, const struct fuse_in_header *header,
                        const char *name, size_t name_length,
                        const struct stat *backing)
{
    struct {
        struct fuse_out_header header;
        struct fuse_entry_out body;
    } response;

    if (header->nodeid != FUSE_ROOT_ID ||
        name_length != sizeof(PROBE_FILE_NAME) ||
        memcmp(name, PROBE_FILE_NAME, sizeof(PROBE_FILE_NAME)) != 0)
        return reply_error(fuse_fd, header, ENOENT);

    memset(&response, 0, sizeof(response));
    response.header.len = sizeof(response);
    response.header.unique = header->unique;
    response.body.nodeid = PROBE_FILE_NODE_ID;
    response.body.generation = 1U;
    response.body.entry_valid = 1U;
    response.body.attr_valid = 1U;
    fill_attr(&response.body.attr, backing, false);
    return write_message(fuse_fd, &response, sizeof(response));
}

static int reply_getattr(int fuse_fd, const struct fuse_in_header *header,
                         const struct stat *backing)
{
    struct {
        struct fuse_out_header header;
        struct fuse_attr_out body;
    } response;

    if (header->nodeid != FUSE_ROOT_ID &&
        header->nodeid != PROBE_FILE_NODE_ID)
        return reply_error(fuse_fd, header, ENOENT);

    memset(&response, 0, sizeof(response));
    response.header.len = sizeof(response);
    response.header.unique = header->unique;
    response.body.attr_valid = 1U;
    fill_attr(&response.body.attr, backing, header->nodeid == FUSE_ROOT_ID);
    return write_message(fuse_fd, &response, sizeof(response));
}

static int reply_open(int fuse_fd, const struct fuse_in_header *header,
                      int backing_fd, struct server_result *result)
{
    struct fuse_backing_map mapping = {
        .fd = backing_fd,
    };
    struct {
        struct fuse_out_header header;
        struct fuse_open_out body;
    } response;
    int backing_id;

    if (header->nodeid != PROBE_FILE_NODE_ID)
        return reply_error(fuse_fd, header, EISDIR);
    backing_id = ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_OPEN, &mapping);
    if (backing_id < 0)
        return -1;
    if (backing_id == 0) {
        errno = EPROTO;
        return -1;
    }

    memset(&response, 0, sizeof(response));
    response.header.len = sizeof(response);
    response.header.unique = header->unique;
    response.body.fh = 1U;
    response.body.open_flags = FOPEN_PASSTHROUGH;
    response.body.backing_id = backing_id;
    result->backing_id = backing_id;
    return write_message(fuse_fd, &response, sizeof(response));
}

static int reply_ordinary_open(int fuse_fd, const struct fuse_in_header *header,
                               const void *payload, size_t payload_length,
                               struct server_result *result)
{
    struct fuse_open_in request;
    struct {
        struct fuse_out_header header;
        struct fuse_open_out body;
    } response;

    if (payload_length != sizeof(request))
        return reply_error(fuse_fd, header, EINVAL);
    memcpy(&request, payload, sizeof(request));
    if (header->nodeid != PROBE_FILE_NODE_ID)
        return reply_error(fuse_fd, header, EISDIR);
    if ((request.flags & O_ACCMODE) != O_RDONLY || (request.flags & O_TRUNC))
        return reply_error(fuse_fd, header, EROFS);
    memset(&response, 0, sizeof(response));
    response.header.len = sizeof(response);
    response.header.unique = header->unique;
    response.body.fh = 1U;
    /* No passthrough flag or backing ID: fstatfs must observe this FUSE inode. */
    result->ordinary_open_requests++;
    return write_message(fuse_fd, &response, sizeof(response));
}

static int reply_statfs(int fuse_fd, const struct fuse_in_header *header,
                        struct server_result *result)
{
    struct {
        struct fuse_out_header header;
        struct fuse_statfs_out body;
    } response;

    memset(&response, 0, sizeof(response));
    response.header.len = sizeof(response);
    response.header.unique = header->unique;
    response.body.st.bsize = 4096U;
    response.body.st.frsize = 4096U;
    response.body.st.namelen = 255U;
    result->statfs_requests++;
    return write_message(fuse_fd, &response, sizeof(response));
}

static int reply_fabricated_verity(int fuse_fd,
                                  const struct fuse_in_header *header,
                                  const void *payload, size_t payload_length,
                                  struct server_result *result)
{
    struct fuse_ioctl_in request;
    struct fsverity_digest digest = {
        .digest_algorithm = FS_VERITY_HASH_ALG_SHA256,
        .digest_size = 32U,
    };
    struct fuse_ioctl_out ioctl_response = {0};
    unsigned char wire[sizeof(struct fuse_out_header) +
                       sizeof(ioctl_response) + sizeof(digest) + 32U];
    struct fuse_out_header response = {
        .len = sizeof(wire),
        .unique = header->unique,
    };
    size_t offset = 0U;

    if (payload_length < sizeof(request))
        return reply_error(fuse_fd, header, EINVAL);
    memcpy(&request, payload, sizeof(request));
    if (header->nodeid != PROBE_FILE_NODE_ID || request.fh != 1U ||
        request.cmd != FS_IOC_MEASURE_VERITY ||
        request.in_size != payload_length - sizeof(request) ||
        request.out_size < sizeof(digest) + 32U)
        return reply_error(fuse_fd, header, ENOTTY);

    /* Linux 6.18 handles this variable-length ioctl explicitly even on ordinary
     * restricted FUSE files: no unrestricted ioctl or retry iovec is needed.
     * These bytes are deliberately fabricated; no backing inode is sealed. */
    memcpy(wire + offset, &response, sizeof(response));
    offset += sizeof(response);
    memcpy(wire + offset, &ioctl_response, sizeof(ioctl_response));
    offset += sizeof(ioctl_response);
    memcpy(wire + offset, &digest, sizeof(digest));
    offset += sizeof(digest);
    memset(wire + offset, 0xa5, 32U);
    result->measurement_requests++;
    return write_message(fuse_fd, wire, sizeof(wire));
}

static int serve_fuse(int fuse_fd, int backing_fd, int result_fd,
                      bool fake_verity)
{
    /* The kernel requires room for the negotiated write size plus request
     * headers on every read, even when this read-only probe expects LOOKUP. */
    unsigned char request_buffer[PROBE_MAX_WRITE + 4096U];
    struct server_result result = {.backing_id = -1};
    struct stat backing;
    bool done = false;

    alarm(20U);
    memset(&backing, 0, sizeof(backing));
    backing.st_size = FAKE_VERITY_FILE_BYTES;
    if (!fake_verity && fstat(backing_fd, &backing) < 0)
        goto failed;

    while (!done) {
        struct fuse_in_header decoded;
        const struct fuse_in_header *header = &decoded;
        const unsigned char *payload;
        size_t payload_length;
        ssize_t length;
        int status = 0;

        do {
            length = read(fuse_fd, request_buffer, sizeof(request_buffer));
        } while (length < 0 && errno == EINTR);
        if (length < 0) {
            if (errno == ENODEV)
                break;
            goto failed;
        }
        if ((size_t)length < sizeof(*header)) {
            errno = EPROTO;
            goto failed;
        }
        memcpy(&decoded, request_buffer, sizeof(decoded));
        if (header->len != (uint32_t)length) {
            errno = EPROTO;
            goto failed;
        }
        payload = request_buffer + sizeof(*header);
        payload_length = (size_t)length - sizeof(*header);

        switch (header->opcode) {
        case FUSE_INIT:
            status = reply_init(fuse_fd, header, payload, payload_length,
                                &result, fake_verity);
            break;
        case FUSE_LOOKUP:
            status = reply_lookup(fuse_fd, header, (const char *)payload,
                                  payload_length, &backing);
            break;
        case FUSE_GETATTR:
            status = reply_getattr(fuse_fd, header, &backing);
            break;
        case FUSE_OPEN:
            status = fake_verity
                         ? reply_ordinary_open(fuse_fd, header, payload,
                                               payload_length, &result)
                         : reply_open(fuse_fd, header, backing_fd, &result);
            break;
        case FUSE_STATFS:
            status = fake_verity ? reply_statfs(fuse_fd, header, &result)
                                 : reply_error(fuse_fd, header, ENOSYS);
            break;
        case FUSE_IOCTL:
            status = fake_verity
                         ? reply_fabricated_verity(fuse_fd, header, payload,
                                                   payload_length, &result)
                         : reply_error(fuse_fd, header, ENOSYS);
            break;
        case FUSE_READ:
            result.read_requests++;
            status = reply_error(fuse_fd, header, EIO);
            break;
        case FUSE_FLUSH:
        case FUSE_RELEASE:
            status = reply_error(fuse_fd, header, 0);
            break;
        case FUSE_FORGET:
            break;
        case FUSE_DESTROY:
            status = reply_error(fuse_fd, header, 0);
            done = true;
            break;
        default:
            status = reply_error(fuse_fd, header, ENOSYS);
            break;
        }
        if (status < 0)
            goto failed;
    }

    if (result.backing_id >= 0) {
        uint32_t backing_id = (uint32_t)result.backing_id;

        if (ioctl(fuse_fd, FUSE_DEV_IOC_BACKING_CLOSE, &backing_id) < 0 &&
            errno != ENODEV)
            goto failed;
    }
    if (write_message(result_fd, &result, sizeof(result)) < 0)
        return 1;
    return 0;

failed:
    result.error_number = errno == 0 ? EIO : errno;
    fprintf(stderr, "FUSE capability server failed: %s\n",
            strerror(result.error_number));
    (void)write_message(result_fd, &result, sizeof(result));
    return 1;
}

static int read_file(const char *path, unsigned char *buffer, size_t capacity,
                     size_t *length_out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    size_t used = 0U;

    if (fd < 0)
        return -1;
    for (;;) {
        ssize_t count = read(fd, buffer + used, capacity - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            close(fd);
            return -1;
        }
        if (count == 0)
            break;
        used += (size_t)count;
        if (used == capacity) {
            unsigned char extra;
            if (read(fd, &extra, 1U) != 0) {
                close(fd);
                errno = EFBIG;
                return -1;
            }
            break;
        }
    }
    if (close(fd) < 0)
        return -1;
    *length_out = used;
    return 0;
}

static int probe_fuse_passthrough(const char *mountpoint,
                                  const char *backing_path)
{
    unsigned char expected[MAXIMUM_PROBE_FILE_BYTES];
    unsigned char observed[MAXIMUM_PROBE_FILE_BYTES];
    char mounted_path[4096];
    char mount_options[256];
    struct server_result result;
    size_t expected_length;
    size_t observed_length;
    int result_pipe[2];
    int fuse_fd;
    int backing_fd;
    pid_t server;
    int server_status;
    ssize_t result_length;
    bool unmounted = false;
    bool reaped = false;

    if (read_file(backing_path, expected, sizeof(expected), &expected_length) <
            0 ||
        expected_length == 0U)
        return 1;
    backing_fd = open(backing_path, O_RDONLY | O_CLOEXEC);
    fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (backing_fd < 0 || fuse_fd < 0)
        return 1;
    if (snprintf(mount_options, sizeof(mount_options),
                 "fd=%d,rootmode=40000,user_id=0,group_id=0,default_permissions",
                 fuse_fd) >= (int)sizeof(mount_options))
        return 1;
    if (mount("aos-fuse-passthrough-proof", mountpoint, "fuse",
              MS_NOSUID | MS_NODEV, mount_options) < 0)
        return 1;
    if (pipe2(result_pipe, O_CLOEXEC) < 0) {
        (void)umount2(mountpoint, MNT_DETACH);
        return 1;
    }

    server = fork();
    if (server < 0) {
        close(result_pipe[0]);
        close(result_pipe[1]);
        (void)umount2(mountpoint, MNT_DETACH);
        return 1;
    }
    if (server == 0) {
        int status;

        close(result_pipe[0]);
        status = serve_fuse(fuse_fd, backing_fd, result_pipe[1], false);
        close(result_pipe[1]);
        close(backing_fd);
        close(fuse_fd);
        _exit(status);
    }

    close(result_pipe[1]);
    close(backing_fd);
    close(fuse_fd);
    if (snprintf(mounted_path, sizeof(mounted_path), "%s/%s", mountpoint,
                 PROBE_FILE_NAME) >= (int)sizeof(mounted_path))
        goto parent_failed;
    if (read_file(mounted_path, observed, sizeof(observed), &observed_length) <
        0)
        goto parent_failed;
    if (umount2(mountpoint, MNT_DETACH) < 0)
        goto parent_failed;
    unmounted = true;

    do {
        result_length = read(result_pipe[0], &result, sizeof(result));
    } while (result_length < 0 && errno == EINTR);
    close(result_pipe[0]);
    if (waitpid(server, &server_status, 0) < 0)
        return 1;
    reaped = true;
    if (result_length != (ssize_t)sizeof(result) ||
        !WIFEXITED(server_status) || WEXITSTATUS(server_status) != 0 ||
        result.error_number != 0 || result.backing_id <= 0 ||
        result.read_requests != 0U || observed_length != expected_length ||
        memcmp(observed, expected, expected_length) != 0) {
        fprintf(stderr, "passthrough proof failed: report-bytes=%zd status=%d "
                "error=%d backing=%d reads=%u bytes=%zu/%zu\n",
                result_length, server_status,
                result_length == (ssize_t)sizeof(result) ? result.error_number : -1,
                result_length == (ssize_t)sizeof(result) ? result.backing_id : -1,
                result_length == (ssize_t)sizeof(result) ? result.read_requests : 0,
                observed_length, expected_length);
        return 1;
    }

    printf("{\"schema_version\":\"aos.sandbox.fuse-passthrough-proof/v1\","
           "\"architecture\":\"%s\",\"fuse_protocol\":\"%u.%u\","
           "\"passthrough_offered\":true,\"backing_registered\":true,"
           "\"passthrough_read\":true,\"userspace_read_requests\":%u}\n",
           architecture(), FUSE_KERNEL_VERSION, result.protocol_minor,
           result.read_requests);
    return 0;

parent_failed:
    perror("FUSE passthrough client");
    if (!unmounted)
        (void)umount2(mountpoint, MNT_DETACH);
    (void)kill(server, SIGKILL);
    if (!reaped)
        (void)waitpid(server, NULL, 0);
    close(result_pipe[0]);
    return 1;
}

static int probe_fake_verity(const char *mountpoint, const char *rust_probe)
{
    char options[256];
    char path[4096];
    struct {
        struct fsverity_digest header;
        unsigned char bytes[32];
    } digest = {.header = {.digest_size = 32U}};
    struct server_result result = {0};
    int report_pipe[2] = {-1, -1};
    int fuse_fd = -1;
    int candidate_fd = -1;
    pid_t server = -1;
    pid_t client = -1;
    int status;
    ssize_t report_bytes;
    bool mounted = false;
    int outcome = 1;

    /* VM-only coordinator: none of these mounts can propagate into another
     * process's mount namespace. Every child has its own finite alarm. */
    alarm(35U);
    if (mountpoint[0] != '/' || rust_probe[0] != '/' ||
        unshare(CLONE_NEWNS) < 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        goto cleanup;
    fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fuse_fd < 0 || pipe2(report_pipe, O_CLOEXEC) < 0)
        goto cleanup;
    if (snprintf(options, sizeof(options),
                 "fd=%d,rootmode=40000,user_id=0,group_id=0,default_permissions",
                 fuse_fd) >= (int)sizeof(options) ||
        snprintf(path, sizeof(path), "%s/%s", mountpoint, PROBE_FILE_NAME) >=
            (int)sizeof(path))
        goto cleanup;
    if (mount("aos-fake-verity-proof", mountpoint, "fuse",
              MS_RDONLY | MS_NOSUID | MS_NODEV, options) < 0)
        goto cleanup;
    mounted = true;
    server = fork();
    if (server < 0)
        goto cleanup;
    if (server == 0) {
        close(report_pipe[0]);
        /* Mount establishment is privileged; fabricating the forwarded ioctl
         * requires only the inherited connection, not mount administration. */
        if (setgroups(0, NULL) < 0 || setresgid(65534, 65534, 65534) < 0 ||
            setresuid(65534, 65534, 65534) < 0)
            _exit(125);
        status = serve_fuse(fuse_fd, -1, report_pipe[1], true);
        close(report_pipe[1]);
        close(fuse_fd);
        _exit(status);
    }
    close(report_pipe[1]);
    report_pipe[1] = -1;
    close(fuse_fd);
    fuse_fd = -1;

    /* Prove the kernel actually forwards and accepts the forged measurement.
     * A plain ENOTTY fixture would not exercise the provenance threat. */
    candidate_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (candidate_fd < 0 ||
        ioctl(candidate_fd, FS_IOC_MEASURE_VERITY, &digest) < 0 ||
        digest.header.digest_algorithm != FS_VERITY_HASH_ALG_SHA256 ||
        digest.header.digest_size != 32U)
        goto cleanup;
    for (size_t i = 0; i < sizeof(digest.bytes); i++) {
        if (digest.bytes[i] != 0xa5)
            goto cleanup;
    }
    close(candidate_fd);
    candidate_fd = -1;

    client = fork();
    if (client < 0)
        goto cleanup;
    if (client == 0) {
        alarm(15U);
        /* No control, report, or FUSE descriptor crosses the exec boundary. */
        if (close_range(3U, UINT_MAX, CLOSE_RANGE_CLOEXEC) < 0)
            _exit(126);
        execl(rust_probe, rust_probe, "--reject-fuse", mountpoint, (char *)NULL);
        _exit(127);
    }
    while (waitpid(client, &status, 0) < 0) {
        if (errno != EINTR)
            goto cleanup;
    }
    client = -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        goto cleanup;

    if (umount2(mountpoint, MNT_DETACH) < 0)
        goto cleanup;
    mounted = false;
    do {
        report_bytes = read(report_pipe[0], &result, sizeof(result));
    } while (report_bytes < 0 && errno == EINTR);
    while (waitpid(server, &status, 0) < 0) {
        if (errno != EINTR)
            goto cleanup;
    }
    server = -1;
    if (report_bytes != (ssize_t)sizeof(result) ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        result.error_number != 0 || result.backing_id != -1 ||
        result.read_requests != 0U || result.measurement_requests != 1U ||
        result.statfs_requests < 2U || result.ordinary_open_requests < 3U)
        goto cleanup;

    printf("{\"schema_version\":\"aos.sandbox.fake-verity-proof/v1\","
           "\"fabricated_ioctl_accepted\":true,"
           "\"measurement_requests\":%u,\"statfs_requests\":%u,"
           "\"ordinary_open_requests\":%u,\"userspace_reads\":0,"
           "\"backing_registered\":false,\"rust_rejected_both\":true}\n",
           result.measurement_requests, result.statfs_requests,
           result.ordinary_open_requests);
    outcome = 0;

cleanup:
    if (outcome != 0)
        fprintf(stderr, "fake-verity proof failed: %s\n", strerror(errno));
    if (candidate_fd >= 0)
        close(candidate_fd);
    if (mounted)
        (void)umount2(mountpoint, MNT_DETACH);
    if (client > 0) {
        (void)kill(client, SIGKILL);
        (void)waitpid(client, NULL, 0);
    }
    if (server > 0) {
        (void)kill(server, SIGKILL);
        (void)waitpid(server, NULL, 0);
    }
    if (fuse_fd >= 0)
        close(fuse_fd);
    if (report_pipe[0] >= 0)
        close(report_pipe[0]);
    if (report_pipe[1] >= 0)
        close(report_pipe[1]);
    alarm(0U);
    return outcome;
}

static int probe_fsverity(const char *path)
{
    struct fsverity_enable_arg enable = {
        .version = 1U,
        .hash_algorithm = FS_VERITY_HASH_ALG_SHA256,
        /* The ioctl requires an explicit power-of-two block size; zero does
         * not select a default. Both harnesses create 4 KiB ext4 blocks. */
        .block_size = 4096U,
    };
    struct {
        struct fsverity_digest header;
        unsigned char bytes[64];
    } digest = {
        .header = {
            .digest_size = sizeof(digest.bytes),
        },
    };
    unsigned long flags = 0U;
    int fd;
    int writable_fd;
    int write_open_errno;
    size_t index;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open fs-verity backing");
        return 1;
    }
    if (ioctl(fd, FS_IOC_ENABLE_VERITY, &enable) < 0) {
        perror("FS_IOC_ENABLE_VERITY");
        close(fd);
        return 1;
    }
    if (ioctl(fd, FS_IOC_MEASURE_VERITY, &digest) < 0) {
        perror("FS_IOC_MEASURE_VERITY");
        close(fd);
        return 1;
    }
    if (digest.header.digest_algorithm != FS_VERITY_HASH_ALG_SHA256 ||
        digest.header.digest_size != 32U) {
        fprintf(stderr, "unexpected fs-verity digest algorithm or length\n");
        close(fd);
        return 1;
    }
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags) < 0 ||
        (flags & FS_VERITY_FL) == 0U) {
        fprintf(stderr, "fs-verity flag missing or unreadable\n");
        close(fd);
        return 1;
    }
    if (close(fd) < 0) {
        perror("close fs-verity backing");
        return 1;
    }

    errno = 0;
    writable_fd = open(path, O_WRONLY | O_CLOEXEC);
    if (writable_fd >= 0) {
        fprintf(stderr, "fs-verity backing unexpectedly permits writable open\n");
        close(writable_fd);
        return 1;
    }
    write_open_errno = errno;
    if (write_open_errno != EPERM) {
        fprintf(stderr, "unexpected writable fs-verity open error: %s\n",
                strerror(write_open_errno));
        return 1;
    }

    printf("{\"schema_version\":\"aos.sandbox.fs-verity-proof/v1\","
           "\"architecture\":\"%s\",\"hash_algorithm\":%u,"
           "\"digest\":\"",
           architecture(), digest.header.digest_algorithm);
    for (index = 0U; index < digest.header.digest_size; index++)
        printf("%02x", digest.bytes[index]);
    printf("\",\"verity_flag\":true,\"write_open_denied\":true,"
           "\"write_open_errno\":%d}\n",
           write_open_errno);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && strcmp(argv[1], "fake-verity") == 0)
        return probe_fake_verity(argv[2], argv[3]);
    if (argc == 3 && strcmp(argv[1], "fs-verity") == 0)
        return probe_fsverity(argv[2]);
    if (argc == 4 && strcmp(argv[1], "fuse-passthrough") == 0)
        return probe_fuse_passthrough(argv[2], argv[3]);

    fprintf(stderr,
            "usage: %s fs-verity FILE | fuse-passthrough MOUNTPOINT BACKING | "
            "fake-verity MOUNTPOINT RUST_PROBE\n",
            argv[0]);
    return 2;
}
