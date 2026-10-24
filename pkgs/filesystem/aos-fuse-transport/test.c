/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 317
#include "aos_fuse_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <fuse_lowlevel.h>
#include <linux/fuse.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_BYTES (1024U * 1024U + 4096U)
#define DEADLINE_MS 2000

/* This is exact-fixture conformance over a trusted fake transport. It does not
 * claim hostile framing safety or replace the real /dev/fuse VM gate. */

struct fake_core {
  int opendir_mode;
  unsigned lookup;
  unsigned forget;
  unsigned getattr;
  unsigned readlink;
  unsigned opendir;
  unsigned readdir;
  unsigned releasedir;
  unsigned destroy;
  unsigned committed;
  unsigned aborted;
  unsigned duplicate_refused;
  unsigned file_open;
  unsigned file_read;
  unsigned file_release;
};

/* Packet scratch is static in this single-thread, fork-isolated fixture.
 * GCC may inline helpers; packet-sized automatic buffers would accumulate
 * in the caller's frame and exceed the standard sandbox stack ceiling. */
union aligned_buffer {
  max_align_t alignment;
  uint8_t bytes[BUFFER_BYTES];
};

static void attributes(struct aos_fuse_attributes *out, uint64_t node,
                       uint8_t kind) {
  memset(out, 0, sizeof(*out));
  out->node_id = node;
  out->size = kind == AOS_FUSE_KIND_SYMLINK ? 6 : 123;
  out->mtime_seconds = 17;
  out->mtime_nanos = 19;
  out->uid = 1000;
  out->gid = 2000;
  out->nlink = kind == AOS_FUSE_KIND_DIRECTORY ? 2 : 1;
  out->mode = kind == AOS_FUSE_KIND_DIRECTORY ? 0755 : 0644;
  out->kind = kind;
}

static int core_lookup(void *opaque, uint64_t parent, const uint8_t *name,
                       uint64_t length, struct aos_fuse_attributes *out) {
  struct fake_core *core = opaque;
  core->lookup++;
  if (parent != 1)
    return ESTALE;
  if (length == 7 && memcmp(name, "missing", 7) == 0)
    return ENOENT;
  if (length != 5 || memcmp(name, "child", 5) != 0)
    return EINVAL;
  attributes(out, 2, AOS_FUSE_KIND_FILE);
  if (core->opendir_mode == 9)
    out->kind = 0;
  if (core->opendir_mode == 11)
    out->size = UINT64_MAX;
  return 0;
}

static int core_forget(void *opaque, uint64_t node, uint64_t count) {
  struct fake_core *core = opaque;
  core->forget++;
  if (core->opendir_mode == 5)
    return AOS_FUSE_CORE_FATAL;
  return node == 2 && count == 1 ? 0 : EINVAL;
}

static int core_getattr(void *opaque, uint64_t node,
                        struct aos_fuse_attributes *out) {
  struct fake_core *core = opaque;
  core->getattr++;
  if (node != 1)
    return ESTALE;
  attributes(out, 1, AOS_FUSE_KIND_DIRECTORY);
  if (core->opendir_mode == 10)
    out->kind = 0;
  return 0;
}

static int core_readlink(void *opaque, uint64_t node, uint8_t *target,
                         uint64_t capacity, uint64_t *length) {
  struct fake_core *core = opaque;
  core->readlink++;
  if (node != 3 || capacity < 6)
    return EINVAL;
  memcpy(target, "target", 6);
  *length = 6;
  return 0;
}

static int core_opendir(void *opaque, uint64_t node,
                        struct aos_fuse_open_responder *responder,
                        aos_fuse_reply_open_fn reply_open) {
  struct fake_core *core = opaque;
  core->opendir++;
  if (node != 1)
    return ENOTDIR;
  if (core->opendir_mode == 3) {
    core->aborted++;
    return AOS_FUSE_CORE_FATAL;
  }
  if (core->opendir_mode == 12)
    return 0;
  int result = reply_open(responder, 77);
  if (result == 0) {
    core->committed++;
    if (reply_open(responder, 88) == EINVAL)
      core->duplicate_refused++;
  } else {
    core->aborted++;
  }
  if (result == 0 && core->opendir_mode == 2)
    return EIO;
  if (result == 0 && core->opendir_mode == 4)
    return AOS_FUSE_CORE_FATAL;
  return result;
}

static int core_readdir(void *opaque, uint64_t node, uint64_t handle,
                        uint64_t cookie, uint64_t maximum_output,
                        struct aos_fuse_directory_entry *entries,
                        uint64_t entry_capacity, uint64_t *entry_count,
                        uint8_t *names, uint64_t names_capacity,
                        uint64_t *names_length) {
  struct fake_core *core = opaque;
  core->readdir++;
  (void)maximum_output;
  if (node != 1 || handle != 77 || cookie != 0 ||
      entry_capacity < 3 || names_capacity < 10)
    return EINVAL;
  memcpy(names, ".\0..\0child", 10);
  entries[0] = (struct aos_fuse_directory_entry){
      .node_id = 1, .next_cookie = 1, .name_offset = 0, .name_length = 1,
      .kind = AOS_FUSE_KIND_DIRECTORY};
  entries[1] = (struct aos_fuse_directory_entry){
      .node_id = 1, .next_cookie = 2, .name_offset = 2, .name_length = 2,
      .kind = AOS_FUSE_KIND_DIRECTORY};
  entries[2] = (struct aos_fuse_directory_entry){
      .node_id = 0, .next_cookie = 3, .name_offset = 5, .name_length = 5,
      .kind = AOS_FUSE_KIND_FILE};
  if (core->opendir_mode == 6)
    entries[0].next_cookie = 0;
  if (core->opendir_mode == 7)
    entries[1].next_cookie = entries[0].next_cookie;
  if (core->opendir_mode == 8) {
    entries[0].next_cookie = 2;
    entries[1].next_cookie = 1;
  }
  *entry_count = 3;
  *names_length = 10;
  return 0;
}

static int core_releasedir(void *opaque, uint64_t node, uint64_t handle) {
  struct fake_core *core = opaque;
  core->releasedir++;
  return node == 1 && handle == 77 ? 0 : ESTALE;
}

static void core_destroy(void *opaque) {
  struct fake_core *core = opaque;
  core->destroy++;
}

static const struct aos_fuse_core_operations operations = {
    .abi_major = AOS_FUSE_TRANSPORT_ABI_MAJOR,
    .abi_minor = AOS_FUSE_TRANSPORT_ABI_MINOR,
    .struct_size = sizeof(operations),
    .attributes_size = sizeof(struct aos_fuse_attributes),
    .directory_entry_size = sizeof(struct aos_fuse_directory_entry),
    .limits_size = sizeof(struct aos_fuse_limits),
    .lookup = core_lookup,
    .forget = core_forget,
    .getattr = core_getattr,
    .readlink = core_readlink,
    .opendir = core_opendir,
    .readdir = core_readdir,
    .releasedir = core_releasedir,
    .destroy = core_destroy,
};

static const struct aos_fuse_limits limits = {
    .struct_size = sizeof(limits),
    .abi_major = AOS_FUSE_TRANSPORT_ABI_MAJOR,
    .abi_minor = AOS_FUSE_TRANSPORT_ABI_MINOR,
    .maximum_name_bytes = 255,
    .maximum_symlink_bytes = 4096,
    .maximum_readdir_bytes = 65536,
    .maximum_readdir_entries = 128,
    .maximum_write_bytes = 65536,
    .maximum_pages = 16,
    .time_granularity_ns = 1,
    .request_timeout_seconds = 2,
    .entry_valid_ns = 1000000000,
    .attribute_valid_ns = 2000000000,
};

static void fail(const char *message) {
  fprintf(stderr, "%s\n", message);
  exit(1);
}

static void send_request(int fd, uint32_t opcode, uint64_t unique,
                         uint64_t node, const void *body, size_t body_length,
                         const void *tail, size_t tail_length) {
  static union aligned_buffer storage;
  uint8_t *packet = storage.bytes;
  size_t length = sizeof(struct fuse_in_header) + body_length + tail_length;
  if (length > sizeof(storage.bytes))
    fail("request exceeds fixture packet");
  memset(packet, 0, length);
  struct fuse_in_header *header = (struct fuse_in_header *)packet;
  header->len = (uint32_t)length;
  header->opcode = opcode;
  header->unique = unique;
  header->nodeid = node;
  header->uid = 1000;
  header->gid = 2000;
  header->pid = (uint32_t)getpid();
  if (body_length != 0)
    memcpy(packet + sizeof(*header), body, body_length);
  if (tail_length != 0)
    memcpy(packet + sizeof(*header) + body_length, tail, tail_length);
  if (send(fd, packet, length, MSG_NOSIGNAL) != (ssize_t)length)
    fail("failed to send request fixture");
}

static size_t receive_reply(int fd, uint64_t unique, uint8_t *buffer,
                            size_t capacity) {
  struct pollfd pollfd = {.fd = fd, .events = POLLIN};
  if (poll(&pollfd, 1, DEADLINE_MS) != 1)
    fail("reply deadline expired");
  ssize_t length = recv(fd, buffer, capacity, 0);
  if (length < (ssize_t)sizeof(struct fuse_out_header)) {
    fprintf(stderr, "truncated reply unique=%llu length=%zd errno=%d\n",
            (unsigned long long)unique, length, errno);
    fail("reply was truncated");
  }
  struct fuse_out_header *header = (struct fuse_out_header *)buffer;
  if (header->len != (uint32_t)length || header->unique != unique)
    fail("reply correlation mismatch");
  return (size_t)length;
}

static void expect_error(int fd, uint64_t unique, int error) {
  static union aligned_buffer storage;
  size_t length = receive_reply(fd, unique, storage.bytes, sizeof(storage.bytes));
  struct fuse_out_header *header = (struct fuse_out_header *)storage.bytes;
  if (length != sizeof(*header) || header->error != -error)
    fail("unexpected error reply");
}

static int core_file_open(void *opaque, uint64_t node, int32_t flags,
                           uint64_t deadline_ns,
                           struct aos_fuse_open_responder *responder,
                           aos_fuse_reply_open_fn reply_open) {
  struct fake_core *core = opaque;
  core->file_open++;
  if (node != 2 || flags != O_RDONLY || deadline_ns == 0)
    return ESTALE;
  int error = reply_open(responder, 91);
  if (error == 0)
    core->committed++;
  else
    core->aborted++;
  return error;
}

static int core_file_read(void *opaque, uint64_t node, uint64_t handle,
                           int64_t offset, uint32_t size, uint64_t deadline_ns,
                           uint8_t *output, uint64_t capacity, uint64_t *length) {
  struct fake_core *core = opaque;
  core->file_read++;
  if (node != 2 || handle != 91)
    return ESTALE;
  if (offset < 0 || size > capacity || deadline_ns == 0)
    return EINVAL;
  if (core->opendir_mode == 2) {
    struct timespec delayed = {.tv_sec = 1, .tv_nsec = 200000000};
    while (nanosleep(&delayed, &delayed) != 0 && errno == EINTR) {}
  }
  static const uint8_t data[] = {'a', 'b', 'c'};
  *length = (uint64_t)offset >= sizeof(data) ? 0 : sizeof(data) - (uint64_t)offset;
  if (*length > size)
    *length = size;
  if (*length != 0)
    memcpy(output, data + (size_t)offset, (size_t)*length);
  /* A provider prefix on error must never enter a kernel reply. */
  return core->opendir_mode == 1 ? EIO : 0;
}

static int core_file_release(void *opaque, uint64_t node, uint64_t handle,
                              int32_t flags, uint32_t release_flags,
                              uint64_t lock_owner, uint64_t deadline_ns) {
  struct fake_core *core = opaque;
  core->file_release++;
  return node == 2 && handle == 91 && flags == O_RDONLY &&
                 release_flags == 0 && lock_owner == 0 && deadline_ns != 0
             ? 0 : ESTALE;
}

static struct aos_fuse_fallback_operations_v2 fallback_operations(void) {
  struct aos_fuse_fallback_operations_v2 result = {
      .abi_major = 2, .abi_minor = 0, .struct_size = sizeof(result),
      .profile = AOS_FUSE_PROFILE_BOUNDED_FALLBACK,
      .open = core_file_open, .read = core_file_read, .release = core_file_release};
  result.metadata = operations;
  return result;
}

static struct aos_fuse_fallback_limits_v2 fallback_limits(void) {
  struct aos_fuse_fallback_limits_v2 result = {
      .abi_major = 2, .abi_minor = 0, .struct_size = sizeof(result),
      .profile = AOS_FUSE_PROFILE_BOUNDED_FALLBACK};
  result.metadata = limits;
  result.metadata.request_timeout_seconds = 1;
  return result;
}

static void test_fallback_v2(void) {
  struct aos_fuse_fallback_operations_v2 ops = fallback_operations();
  struct aos_fuse_fallback_limits_v2 bounds = fallback_limits();
  if (sizeof(ops) != 136 || sizeof(bounds) != 80 ||
      offsetof(struct aos_fuse_fallback_operations_v2, open) != 112)
    fail("fallback ABI width or V1 embedding changed");
  for (unsigned variant = 0; variant < 6; variant++) {
    struct aos_fuse_fallback_operations_v2 bad = ops;
    struct aos_fuse_fallback_limits_v2 bad_bounds = bounds;
    switch (variant) {
    case 0: bad.abi_major = 1; break;
    case 1: bad.abi_minor = 1; break;
    case 2: bad.profile = 2; break;
    case 3: bad.metadata.flags = 1; break;
    case 4: bad_bounds.abi_major = 1; break;
    default: bad_bounds.reserved = 1; break;
    }
    if (aos_fuse_transport_run_fallback_v2_test_fd(-1, -1, &bad, NULL, &bad_bounds) != EINVAL)
      fail("mixed fallback contract was not rejected before descriptor use");
  }

  for (int mode = 0; mode <= 2; mode++) {
    int sockets[2];
    int cancellation[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) != 0 ||
        pipe2(cancellation, O_CLOEXEC | O_NONBLOCK) != 0)
      fail("fallback fixture descriptors failed");
    pid_t child = fork();
    if (child < 0)
      fail("fallback fork failed");
    if (child == 0) {
      signal(SIGPIPE, SIG_IGN);
      close(sockets[0]);
      close(cancellation[1]);
      struct fake_core core = {.opendir_mode = mode};
      int result = aos_fuse_transport_run_fallback_v2_test_fd(
          sockets[1], cancellation[0], &ops, &core, &bounds);
      bool valid = result == (mode == 2 ? ETIMEDOUT : ECANCELED) &&
                   core.destroy == 1 && core.file_open == 1 && core.committed == 1 &&
                   fcntl(sockets[1], F_GETFD) >= 0 && fcntl(cancellation[0], F_GETFD) >= 0;
      close(sockets[1]);
      close(cancellation[0]);
      _exit(valid ? 0 : 3);
    }
    close(sockets[1]);
    close(cancellation[0]);
    static union aligned_buffer reply;
    struct fuse_init_in init = {.major = 7, .minor = 45, .flags = FUSE_INIT_EXT | FUSE_MAX_PAGES,
                               .flags2 = (uint32_t)(FUSE_REQUEST_TIMEOUT >> 32)};
    send_request(sockets[0], FUSE_INIT, 1, 0, &init, sizeof(init), NULL, 0);
    (void)receive_reply(sockets[0], 1, reply.bytes, sizeof(reply.bytes));
    struct fuse_open_in open = {.flags = O_RDONLY};
    send_request(sockets[0], FUSE_OPEN, 2, 2, &open, sizeof(open), NULL, 0);
    size_t received = receive_reply(sockets[0], 2, reply.bytes, sizeof(reply.bytes));
    struct fuse_out_header *header = (struct fuse_out_header *)reply.bytes;
    struct fuse_open_out *opened = (struct fuse_open_out *)(header + 1);
    if (received != sizeof(*header) + sizeof(*opened) || header->error != 0 ||
        opened->fh != 91 || opened->open_flags != FOPEN_DIRECT_IO)
      fail("fallback OPEN did not publish exact direct-I/O handle");
    struct fuse_read_in read = {.fh = 91, .offset = 0, .size = 4};
    send_request(sockets[0], FUSE_READ, 3, 2, &read, sizeof(read), NULL, 0);
    if (mode == 2) {
      /* No fresh reply timeout may let a slow core publish after its bound. */
      struct pollfd waiting = {.fd = sockets[0], .events = POLLIN | POLLHUP};
      if (poll(&waiting, 1, 1800) < 0)
        fail("expired fallback request observation failed");
      if ((waiting.revents & POLLIN) != 0 &&
          recv(sockets[0], reply.bytes, sizeof(reply.bytes), MSG_DONTWAIT) > 0)
        fail("expired fallback request published a late reply");
    } else if (mode == 1) {
      expect_error(sockets[0], 3, EIO);
    } else {
      received = receive_reply(sockets[0], 3, reply.bytes, sizeof(reply.bytes));
      if (received != sizeof(*header) + 3 || header->error != 0 || memcmp(header + 1, "abc", 3) != 0)
        fail("fallback READ did not return exact verified length");
      read.offset = 3;
      send_request(sockets[0], FUSE_READ, 4, 2, &read, sizeof(read), NULL, 0);
      received = receive_reply(sockets[0], 4, reply.bytes, sizeof(reply.bytes));
      if (received != sizeof(*header) || header->error != 0)
        fail("fallback EOF was not an empty successful reply");
      read.fh = 92;
      send_request(sockets[0], FUSE_READ, 5, 2, &read, sizeof(read), NULL, 0);
      expect_error(sockets[0], 5, ESTALE);
      read.fh = 91;
      read.size = limits.maximum_write_bytes + 1;
      send_request(sockets[0], FUSE_READ, 6, 2, &read, sizeof(read), NULL, 0);
      expect_error(sockets[0], 6, ENOMEM);
      struct fuse_release_in release = {.fh = 91, .flags = O_RDONLY};
      send_request(sockets[0], FUSE_RELEASE, 7, 2, &release, sizeof(release), NULL, 0);
      expect_error(sockets[0], 7, 0);
    }
    if (mode != 2 && write(cancellation[1], "x", 1) != 1)
      fail("fallback cancellation failed");
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
      fail("fallback teardown or borrowed-FD contract failed");
    close(sockets[0]);
    close(cancellation[1]);
  }
}

static pid_t start_child(int sockets[2], int cancellation[2],
                         int opendir_mode) {
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                 sockets) != 0)
    fail("socketpair failed");
  if (pipe2(cancellation, O_CLOEXEC | O_NONBLOCK) != 0)
    fail("cancellation pipe failed");
  pid_t child = fork();
  if (child < 0)
    fail("fork failed");
  if (child == 0) {
    signal(SIGPIPE, SIG_IGN);
    close(sockets[0]);
    close(cancellation[1]);
    struct fake_core core = {0};
    core.opendir_mode = opendir_mode;
    int fd = sockets[1];
    int result = aos_fuse_transport_run_test_fd(fd, cancellation[0], &operations,
                                                &core, &limits);
    if (opendir_mode >= 6 && opendir_mode <= 12) {
      struct timespec delay = {.tv_sec = 0, .tv_nsec = 200000000};
      nanosleep(&delay, NULL);
    }
    int descriptor_borrowed = fcntl(fd, F_GETFD) >= 0;
    int cancellation_borrowed = fcntl(cancellation[0], F_GETFD) >= 0;
    int valid;
    if (opendir_mode == 1) {
      valid = result == EPIPE && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 0 && core.forget == 0 && core.getattr == 0 &&
              core.readlink == 0 && core.opendir == 1 && core.readdir == 0 &&
              core.releasedir == 0 && core.committed == 0 &&
              core.aborted == 1 && core.duplicate_refused == 0 &&
              core.destroy == 1;
    } else if (opendir_mode == 2 || opendir_mode == 4) {
      valid = result == EIO && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 0 && core.forget == 0 && core.getattr == 0 &&
              core.readlink == 0 && core.opendir == 1 && core.readdir == 0 &&
              core.releasedir == 0 && core.committed == 1 &&
              core.aborted == 0 && core.duplicate_refused == 1 &&
              core.destroy == 1;
    } else if (opendir_mode == 3) {
      valid = result == EIO && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 0 && core.forget == 0 && core.getattr == 0 &&
              core.readlink == 0 && core.opendir == 1 && core.readdir == 0 &&
              core.releasedir == 0 && core.committed == 0 &&
              core.aborted == 1 && core.duplicate_refused == 0 &&
              core.destroy == 1;
    } else if (opendir_mode == 5) {
      valid = result == EIO && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 0 && core.forget == 1 && core.getattr == 0 &&
              core.readlink == 0 && core.opendir == 0 && core.readdir == 0 &&
              core.releasedir == 0 && core.committed == 0 &&
              core.aborted == 0 && core.duplicate_refused == 0 &&
              core.destroy == 1;
    } else if (opendir_mode >= 6 && opendir_mode <= 8) {
      valid = result == EIO && descriptor_borrowed &&
              cancellation_borrowed && core.lookup == 0 && core.forget == 0 &&
              core.getattr == 0 && core.readlink == 0 && core.opendir == 1 &&
              core.readdir == 1 && core.releasedir == 0 &&
              core.committed == 1 && core.aborted == 0 &&
              core.duplicate_refused == 1 && core.destroy == 1;
    } else if (opendir_mode == 9 || opendir_mode == 11) {
      valid = result == EIO && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 1 && core.forget == 0 && core.getattr == 0 &&
              core.readlink == 0 && core.opendir == 0 && core.readdir == 0 &&
              core.releasedir == 0 && core.committed == 0 &&
              core.aborted == 0 && core.duplicate_refused == 0 &&
              core.destroy == 1;
    } else if (opendir_mode == 10) {
      valid = result == EIO && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 0 && core.forget == 0 && core.getattr == 1 &&
              core.readlink == 0 && core.opendir == 0 && core.readdir == 0 &&
              core.releasedir == 0 && core.committed == 0 &&
              core.aborted == 0 && core.duplicate_refused == 0 &&
              core.destroy == 1;
    } else if (opendir_mode == 12) {
      valid = result == EIO && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 0 && core.forget == 0 && core.getattr == 0 &&
              core.readlink == 0 && core.opendir == 1 && core.readdir == 0 &&
              core.releasedir == 0 && core.committed == 0 &&
              core.aborted == 0 && core.duplicate_refused == 0 &&
              core.destroy == 1;
    } else {
      valid = result == ECANCELED && descriptor_borrowed && cancellation_borrowed &&
              core.lookup == 2 && core.forget == 1 && core.getattr == 1 &&
              core.readlink == 1 && core.opendir == 1 && core.readdir == 4 &&
              core.releasedir == 1 && core.committed == 1 &&
              core.aborted == 0 && core.duplicate_refused == 1 &&
              core.destroy == 1;
    }
    if (!valid)
      fprintf(stderr,
              "mode=%d result=%d borrowed=%d cancel=%d calls=%u/%u/%u/%u/%u/%u/%u commit=%u abort=%u duplicate=%u destroy=%u\n",
              opendir_mode, result, descriptor_borrowed, cancellation_borrowed,
              core.lookup, core.forget, core.getattr, core.readlink,
              core.opendir, core.readdir, core.releasedir, core.committed,
              core.aborted, core.duplicate_refused, core.destroy);
    close(fd);
    _exit(valid ? 0 : 2);
  }
  close(sockets[1]);
  close(cancellation[0]);
  return child;
}

static void wait_child(pid_t child) {
  for (int attempt = 0; attempt < 200; ++attempt) {
    int status = 0;
    pid_t result = waitpid(child, &status, WNOHANG);
    if (result == child) {
      if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        fail("transport child failed lifecycle assertions");
      return;
    }
    if (result < 0)
      fail("waitpid failed");
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000};
    nanosleep(&delay, NULL);
  }
  kill(child, SIGKILL);
  fail("transport teardown deadline expired");
}

/* Fake transport exercises C lifetime/framing only, not genuine kernel INIT,
 * namespace idmap, actual worker custody or a Root/Mount read grant. */
static void prepared_session_case(unsigned scenario) {
  int sockets[2];
  int cancellation[2];
  int prepared_notice[2];
  int continuation[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                 sockets) != 0 ||
      pipe2(cancellation, O_CLOEXEC | O_NONBLOCK) != 0 ||
      pipe2(prepared_notice, O_CLOEXEC) != 0 ||
      pipe2(continuation, O_CLOEXEC) != 0)
    fail("prepared lifecycle fixture descriptors failed");
  pid_t child = fork();
  if (child < 0)
    fail("prepared lifecycle fork failed");
  if (child == 0) {
    signal(SIGPIPE, SIG_IGN);
    close(sockets[0]);
    close(cancellation[1]);
    close(prepared_notice[0]);
    close(continuation[1]);
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0)
      _exit(2);
    struct aos_fuse_preparation_v1 preparation = {
        .struct_size = sizeof(preparation),
        .abi_major = AOS_FUSE_PREPARED_SESSION_ABI_MAJOR,
        .abi_minor = AOS_FUSE_PREPARED_SESSION_ABI_MINOR,
        .deadline_boottime_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                               (uint64_t)now.tv_nsec +
                               (scenario == 5 ? UINT64_C(50000000)
                                              : UINT64_C(2000000000)),
        .limits = limits,
    };
    struct aos_fuse_prepared_session_v1 *prepared = NULL;
    int result = aos_fuse_transport_prepare_test_fd_v1(
        sockets[1], cancellation[0], &preparation, &prepared);
    if (scenario != 0) {
      int expected = scenario == 5 ? ETIMEDOUT : EPROTO;
      _exit(result == expected && prepared == NULL &&
                    fcntl(sockets[1], F_GETFD) >= 0 &&
                    fcntl(cancellation[0], F_GETFD) >= 0
                ? 0
                : 2);
    }
    if (result != 0 || prepared == NULL ||
        write(prepared_notice[1], "p", 1) != 1)
      _exit(2);
    struct pollfd gate = {.fd = continuation[0], .events = POLLIN};
    char signal_byte;
    if (poll(&gate, 1, DEADLINE_MS) != 1 ||
        read(continuation[0], &signal_byte, 1) != 1 || signal_byte != 'c')
      _exit(2);
    struct fake_core core = {0};
    result = aos_fuse_transport_continue_prepared_v1(prepared, &operations,
                                                     &core);
    int valid = result == ECANCELED && core.getattr == 1 && core.destroy == 1 &&
                aos_fuse_transport_continue_prepared_v1(
                    prepared, &operations, &core) == EINVAL &&
                fcntl(sockets[1], F_GETFD) >= 0 &&
                fcntl(cancellation[0], F_GETFD) >= 0;
    aos_fuse_transport_destroy_prepared_v1(prepared);
    _exit(valid && core.destroy == 1 ? 0 : 2);
  }
  close(sockets[1]);
  close(cancellation[0]);
  close(prepared_notice[1]);
  close(continuation[0]);

  struct fuse_init_in init = {
      .major = 7,
      .minor = scenario == 3 ? 44U : 45U,
      .flags = FUSE_INIT_EXT | FUSE_MAX_PAGES,
      .flags2 = (uint32_t)((FUSE_ALLOW_IDMAP | FUSE_REQUEST_TIMEOUT) >> 32),
  };
  if (scenario == 1)
    init.flags2 &= ~(uint32_t)(FUSE_ALLOW_IDMAP >> 32);
  if (scenario == 4)
    init.unused[0] = 1;
  if (scenario != 5)
    send_request(sockets[0], scenario == 2 ? FUSE_GETATTR : FUSE_INIT, 101,
                 0, &init, sizeof(init), NULL, 0);
  if (scenario == 0) {
    static union aligned_buffer reply;
    size_t length = receive_reply(sockets[0], 101, reply.bytes,
                                  sizeof(reply.bytes));
    struct fuse_out_header *header = (struct fuse_out_header *)reply.bytes;
    struct fuse_init_out *body = (struct fuse_init_out *)(header + 1);
    if (length != sizeof(*header) + sizeof(*body) || header->error != 0 ||
        body->major != 7 || body->minor != 45 ||
        !(body->flags2 & (uint32_t)(FUSE_ALLOW_IDMAP >> 32)))
      fail("prepared session did not select exact offered IDMAP");
    struct pollfd notice = {.fd = prepared_notice[0], .events = POLLIN};
    char byte;
    if (poll(&notice, 1, DEADLINE_MS) != 1 ||
        read(prepared_notice[0], &byte, 1) != 1 || byte != 'p')
      fail("prepared session boundary was not reached");
    struct fuse_getattr_in getattr = {0};
    send_request(sockets[0], FUSE_GETATTR, 102, 1, &getattr, sizeof(getattr),
                 NULL, 0);
    struct pollfd idle = {.fd = sockets[0], .events = POLLIN};
    if (poll(&idle, 1, 30) != 0)
      fail("prepared session dispatched metadata before continuation");
    if (write(continuation[1], "c", 1) != 1)
      fail("prepared continuation fixture release failed");
    length = receive_reply(sockets[0], 102, reply.bytes, sizeof(reply.bytes));
    header = (struct fuse_out_header *)reply.bytes;
    if (length != sizeof(*header) + sizeof(struct fuse_attr_out) ||
        header->error != 0)
      fail("same initialized session failed direct metadata continuation");
    close(cancellation[1]);
  }
  wait_child(child);
  if (scenario != 0)
    close(cancellation[1]);
  close(sockets[0]);
  close(prepared_notice[0]);
  close(continuation[1]);
}

#include "scoped_reply_test.c.inc"

int main(void) {
  if (fuse_version() != 318)
    fail("runtime libfuse version differs from the qualified 3.18.2 ABI");
  test_scoped_reply_v3();
  test_fallback_v2();
  for (unsigned scenario = 0; scenario <= 5; scenario++)
    prepared_session_case(scenario);

  int short_sockets[2];
  int short_cancellation[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                 short_sockets) != 0 ||
      pipe2(short_cancellation, O_CLOEXEC | O_NONBLOCK) != 0)
    fail("short-write fixture descriptors failed");
  int send_buffer = 4096;
  if (setsockopt(short_sockets[0], SOL_SOCKET, SO_SNDBUF, &send_buffer,
                 sizeof(send_buffer)) != 0)
    fail("short-write send buffer setup failed");
  static union aligned_buffer short_payload;
  memset(short_payload.bytes, 0x5a, sizeof(short_payload.bytes));
  int short_terminal = 0;
  size_t first_length = sizeof(short_payload.bytes) / 2;
  if (aos_fuse_transport_test_writev(
          short_sockets[0], short_cancellation[0], short_payload.bytes,
          first_length, short_payload.bytes + first_length,
          sizeof(short_payload.bytes) - first_length, 1, &short_terminal) !=
          -1 ||
      short_terminal != EIO)
    fail("positive short record write did not terminate with EIO");
  uint8_t drained[4096];
  size_t drained_length = 0;
  for (;;) {
    ssize_t amount = recv(short_sockets[1], drained, sizeof(drained), 0);
    if (amount > 0) {
      drained_length += (size_t)amount;
      continue;
    }
    if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      break;
    fail("short-write fixture drain failed");
  }
  if (drained_length == 0 || drained_length >= sizeof(short_payload.bytes))
    fail("short-write fixture did not produce a positive partial record");
  close(short_sockets[0]);
  close(short_sockets[1]);
  close(short_cancellation[0]);
  close(short_cancellation[1]);

  int contract_sockets[2];
  int contract_cancellation[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                 contract_sockets) != 0 ||
      pipe2(contract_cancellation, O_CLOEXEC | O_NONBLOCK) != 0)
    fail("contract fixture descriptors failed");
  struct aos_fuse_core_operations bad_operations = operations;
  if (aos_fuse_transport_run_test_fd(
          contract_sockets[0], contract_sockets[0], &operations, NULL,
          &limits) != EINVAL ||
      fcntl(contract_sockets[0], F_GETFD) < 0)
    fail("identical descriptor roles were not rejected atomically");
  int aliased_descriptor = dup(contract_sockets[0]);
  if (aliased_descriptor < 0 ||
      aos_fuse_transport_run_test_fd(contract_sockets[0], aliased_descriptor,
                                     &operations, NULL, &limits) != EINVAL ||
      fcntl(contract_sockets[0], F_GETFD) < 0)
    fail("aliased descriptor roles were not rejected atomically");
  close(aliased_descriptor);
  int original_flags = fcntl(contract_sockets[0], F_GETFL);
  if (original_flags < 0 ||
      fcntl(contract_sockets[0], F_SETFL, original_flags & ~O_NONBLOCK) != 0 ||
      aos_fuse_transport_run_test_fd(
          contract_sockets[0], contract_cancellation[0], &operations, NULL,
          &limits) != EBADF ||
      fcntl(contract_sockets[0], F_SETFL, original_flags) != 0)
    fail("blocking transport descriptor was not rejected atomically");
  if (aos_fuse_transport_run_test_fd(
          contract_sockets[0], contract_cancellation[1], &operations, NULL,
          &limits) != EBADF ||
      fcntl(contract_sockets[0], F_GETFD) < 0)
    fail("write-only cancellation descriptor was not rejected atomically");
  bad_operations.flags = 1;
  if (aos_fuse_transport_run_test_fd(
          contract_sockets[0], contract_cancellation[0], &bad_operations, NULL,
          &limits) != EINVAL ||
      fcntl(contract_sockets[0], F_GETFD) < 0)
    fail("unknown operation-table flags were not rejected atomically");
  struct aos_fuse_limits bad_limits = limits;
  bad_limits.abi_minor++;
  if (aos_fuse_transport_run_test_fd(
          contract_sockets[0], contract_cancellation[0], &operations, NULL,
          &bad_limits) != EINVAL ||
      fcntl(contract_sockets[0], F_GETFD) < 0)
    fail("future limit ABI was not rejected atomically");
  bad_limits = limits;
  bad_limits.entry_valid_ns = UINT64_C(86400000000001);
  if (aos_fuse_transport_run_test_fd(
          contract_sockets[0], contract_cancellation[0], &operations, NULL,
          &bad_limits) != EINVAL ||
      fcntl(contract_sockets[0], F_GETFD) < 0)
    fail("oversized TTL was not rejected atomically");
  bad_limits = limits;
  bad_limits.maximum_pages--;
  if (aos_fuse_transport_run_test_fd(
          contract_sockets[0], contract_cancellation[0], &operations, NULL,
          &bad_limits) != EINVAL ||
      fcntl(contract_sockets[0], F_GETFD) < 0)
    fail("inexact write-to-page ceiling was not rejected atomically");
  close(contract_sockets[0]);
  close(contract_sockets[1]);
  close(contract_cancellation[0]);
  close(contract_cancellation[1]);

  int rejected[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                 rejected) != 0)
    fail("rejection socketpair failed");
  if (aos_fuse_transport_run(rejected[0], rejected[1], &operations, NULL,
                             &limits) != ENODEV)
    fail("production entry accepted a non-FUSE descriptor");
  if (fcntl(rejected[0], F_GETFD) < 0)
    fail("rejected descriptor ownership changed");
  close(rejected[0]);
  close(rejected[1]);

  int sockets[2];
  int cancellation[2];
  pid_t child = start_child(sockets, cancellation, 0);
  uint64_t unique = 1;
  static union aligned_buffer reply_storage;
  uint8_t *reply = reply_storage.bytes;

  struct fuse_init_in init = {
      .major = 7,
      .minor = 45,
      .max_readahead = 0,
      .flags = FUSE_INIT_EXT | FUSE_MAX_PAGES,
      .flags2 = (uint32_t)(FUSE_REQUEST_TIMEOUT >> 32),
  };
  send_request(sockets[0], FUSE_INIT, unique, 0, &init, sizeof(init), NULL, 0);
  size_t length =
      receive_reply(sockets[0], unique++, reply, sizeof(reply_storage.bytes));
  if (length != sizeof(struct fuse_out_header) + sizeof(struct fuse_init_out))
    fail("INIT reply size was not exact ABI 7.45");
  struct fuse_out_header *out = (struct fuse_out_header *)reply;
  struct fuse_init_out *init_out = (struct fuse_init_out *)(out + 1);
  uint32_t allowed_flags = FUSE_INIT_EXT | FUSE_MAX_PAGES | FUSE_BIG_WRITES;
  uint32_t allowed_flags2 = (uint32_t)(FUSE_REQUEST_TIMEOUT >> 32);
  if (out->error != 0 || init_out->major != 7 || init_out->minor != 45 ||
      init_out->max_readahead != 0 ||
      init_out->max_write != limits.maximum_write_bytes ||
      init_out->max_pages != limits.maximum_pages ||
      init_out->time_gran != limits.time_granularity_ns ||
      init_out->max_background != 1 || init_out->congestion_threshold != 1 ||
      init_out->request_timeout != limits.request_timeout_seconds ||
      init_out->flags != allowed_flags || init_out->flags2 != allowed_flags2) {
    fprintf(stderr,
            "init actual: readahead=%u write=%u pages=%u gran=%u background=%u congestion=%u timeout=%u flags=%#x flags2=%#x\n",
            init_out->max_readahead, init_out->max_write,
            init_out->max_pages, init_out->time_gran,
            init_out->max_background, init_out->congestion_threshold,
            init_out->request_timeout, init_out->flags, init_out->flags2);
    fail("INIT negotiation exceeded conservative ceilings");
  }

  send_request(sockets[0], FUSE_LOOKUP, unique, 1, NULL, 0, "", 1);
  expect_error(sockets[0], unique++, EINVAL);
  send_request(sockets[0], FUSE_LOOKUP, unique, 1, NULL, 0, "bad/name", 9);
  expect_error(sockets[0], unique++, EINVAL);
  char overlong_name[257];
  memset(overlong_name, 'x', sizeof(overlong_name));
  overlong_name[sizeof(overlong_name) - 1] = '\0';
  send_request(sockets[0], FUSE_LOOKUP, unique, 1, NULL, 0, overlong_name,
               sizeof(overlong_name));
  expect_error(sockets[0], unique++, ENAMETOOLONG);

  send_request(sockets[0], FUSE_LOOKUP, unique, 1, NULL, 0, "child", 6);
  length = receive_reply(sockets[0], unique++, reply,
                         sizeof(reply_storage.bytes));
  if (length != sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out) ||
      ((struct fuse_out_header *)reply)->error != 0 ||
      ((struct fuse_entry_out *)(reply + sizeof(struct fuse_out_header)))->nodeid != 2)
    fail("LOOKUP reply was invalid");

  send_request(sockets[0], FUSE_LOOKUP, unique, 1, NULL, 0, "missing", 8);
  length = receive_reply(sockets[0], unique++, reply,
                         sizeof(reply_storage.bytes));
  if (length != sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out) ||
      ((struct fuse_entry_out *)(reply + sizeof(struct fuse_out_header)))->nodeid != 0)
    fail("negative LOOKUP was not an entry reply");

  struct fuse_forget_in forget = {.nlookup = 1};
  send_request(sockets[0], FUSE_FORGET, unique++, 2, &forget, sizeof(forget), NULL, 0);
  struct pollfd no_reply = {.fd = sockets[0], .events = POLLIN};
  if (poll(&no_reply, 1, 50) != 0)
    fail("FORGET produced a reply");

  struct fuse_getattr_in getattr = {0};
  send_request(sockets[0], FUSE_GETATTR, unique, 1, &getattr, sizeof(getattr), NULL, 0);
  length = receive_reply(sockets[0], unique++, reply,
                         sizeof(reply_storage.bytes));
  if (length != sizeof(struct fuse_out_header) + sizeof(struct fuse_attr_out) ||
      ((struct fuse_attr_out *)(reply + sizeof(struct fuse_out_header)))->attr.ino != 1)
    fail("GETATTR reply was invalid");

  send_request(sockets[0], FUSE_READLINK, unique, 3, NULL, 0, NULL, 0);
  length = receive_reply(sockets[0], unique++, reply,
                         sizeof(reply_storage.bytes));
  if (length != sizeof(struct fuse_out_header) + 6 ||
      memcmp(reply + sizeof(struct fuse_out_header), "target", 6) != 0)
    fail("READLINK reply was invalid");

  struct fuse_open_in open = {0};
  send_request(sockets[0], FUSE_OPENDIR, unique, 1, &open, sizeof(open), NULL, 0);
  length = receive_reply(sockets[0], unique++, reply,
                         sizeof(reply_storage.bytes));
  struct fuse_open_out *open_out =
      (struct fuse_open_out *)(reply + sizeof(struct fuse_out_header));
  if (length != sizeof(struct fuse_out_header) + sizeof(*open_out) ||
      open_out->fh != 77)
    fail("OPENDIR reply was invalid");

  struct fuse_read_in read = {.fh = 77, .offset = 0, .size = 4096};
  send_request(sockets[0], FUSE_READDIR, unique, 1, &read, sizeof(read), NULL, 0);
  length = receive_reply(sockets[0], unique++, reply,
                         sizeof(reply_storage.bytes));
  size_t position = sizeof(struct fuse_out_header);
  uint64_t cookies[3] = {1, 2, 3};
  const char *names[3] = {".", "..", "child"};
  for (size_t index = 0; index < 3; ++index) {
    if (position + sizeof(struct fuse_dirent) > length)
      fail("READDIR record truncated");
    struct fuse_dirent *entry = (struct fuse_dirent *)(reply + position);
    if (entry->off != cookies[index] ||
        entry->namelen != (uint32_t)strlen(names[index]) ||
        memcmp(entry->name, names[index], entry->namelen) != 0)
      fail("READDIR entry or cookie mismatch");
    position += FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + entry->namelen);
  }
  if (position != length)
    fail("READDIR alignment or tail was invalid");

  struct fuse_read_in tiny_read = {.fh = 77, .offset = 0, .size = 1};
  send_request(sockets[0], FUSE_READDIR, unique, 1, &tiny_read,
               sizeof(tiny_read), NULL, 0);
  expect_error(sockets[0], unique++, EINVAL);
  tiny_read.size = 0;
  send_request(sockets[0], FUSE_READDIR, unique, 1, &tiny_read,
               sizeof(tiny_read), NULL, 0);
  expect_error(sockets[0], unique++, EINVAL);

  struct fuse_read_in small_read = {.fh = 77, .offset = 0, .size = 64};
  send_request(sockets[0], FUSE_READDIR, unique, 1, &small_read,
               sizeof(small_read), NULL, 0);
  length = receive_reply(sockets[0], unique++, reply,
                         sizeof(reply_storage.bytes));
  position = sizeof(struct fuse_out_header);
  uint64_t last_cookie = 0;
  while (position < length) {
    struct fuse_dirent *entry = (struct fuse_dirent *)(reply + position);
    last_cookie = entry->off;
    position += FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + entry->namelen);
  }
  if (position != length || last_cookie != 2)
    fail("bounded READDIR did not continue from the last packed cookie");

  struct fuse_release_in release = {.fh = 77};
  send_request(sockets[0], FUSE_RELEASEDIR, unique, 1, &release, sizeof(release), NULL, 0);
  expect_error(sockets[0], unique++, 0);

  struct fuse_mkdir_in mkdir = {.mode = 0755, .umask = 0022};
  send_request(sockets[0], FUSE_MKDIR, unique, 1, &mkdir, sizeof(mkdir), "new", 4);
  expect_error(sockets[0], unique++, EROFS);

  struct fuse_access_in access = {.mask = R_OK};
  send_request(sockets[0], FUSE_ACCESS, unique, 1, &access, sizeof(access),
               NULL, 0);
  expect_error(sockets[0], unique++, ENOTSUP);

  struct fuse_copy_file_range_in copy = {
      .fh_in = 1, .off_in = 0, .nodeid_out = 2, .fh_out = 2, .off_out = 0,
      .len = 1, .flags = 0};
  send_request(sockets[0], FUSE_COPY_FILE_RANGE, unique, 1, &copy,
               sizeof(copy), NULL, 0);
  expect_error(sockets[0], unique++, EROFS);

  send_request(sockets[0], FUSE_READDIRPLUS, unique, 1, &read, sizeof(read), NULL, 0);
  expect_error(sockets[0], unique++, ENOTSUP);
  send_request(sockets[0], 99, unique, 1, NULL, 0, NULL, 0);
  expect_error(sockets[0], unique++, ENOSYS);

  if (write(cancellation[1], "x", 1) != 1)
    fail("failed to request cancellation");
  close(cancellation[1]);
  close(sockets[0]);
  wait_child(child);

  int idle_sockets[2];
  int idle_cancellation[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                 idle_sockets) != 0 ||
      pipe2(idle_cancellation, O_CLOEXEC | O_NONBLOCK) != 0)
    fail("idle fixture descriptors failed");
  child = fork();
  if (child < 0)
    fail("idle fixture fork failed");
  if (child == 0) {
    close(idle_sockets[0]);
    close(idle_cancellation[1]);
    struct fake_core core = {0};
    struct aos_fuse_limits idle_limits = limits;
    idle_limits.request_timeout_seconds = 1;
    int fd = idle_sockets[1];
    int result = aos_fuse_transport_run_test_fd(
        fd, idle_cancellation[0], &operations, &core, &idle_limits);
    int valid = result == ECANCELED && core.lookup == 0 && core.forget == 0 &&
                core.getattr == 0 && core.readlink == 0 && core.opendir == 0 &&
                core.readdir == 0 && core.releasedir == 0 &&
                core.destroy == 1 && fcntl(fd, F_GETFD) >= 0;
    close(fd);
    _exit(valid ? 0 : 2);
  }
  close(idle_sockets[1]);
  close(idle_cancellation[0]);
  unique = 90;
  send_request(idle_sockets[0], FUSE_INIT, unique, 0, &init, sizeof(init),
               NULL, 0);
  (void)receive_reply(idle_sockets[0], unique, reply,
                      sizeof(reply_storage.bytes));
  struct timespec idle_delay = {.tv_sec = 1, .tv_nsec = 200000000};
  nanosleep(&idle_delay, NULL);
  int idle_status = 0;
  if (waitpid(child, &idle_status, WNOHANG) != 0)
    fail("healthy idle transport expired at the active-request timeout");
  if (write(idle_cancellation[1], "x", 1) != 1)
    fail("idle fixture cancellation failed");
  close(idle_cancellation[1]);
  close(idle_sockets[0]);
  wait_child(child);

  int failed_sockets[2];
  int failed_cancellation[2];
  child = start_child(failed_sockets, failed_cancellation, 1);
  unique = 100;
  send_request(failed_sockets[0], FUSE_INIT, unique, 0, &init, sizeof(init),
               NULL, 0);
  (void)receive_reply(failed_sockets[0], unique++, reply,
                      sizeof(reply_storage.bytes));
  send_request(failed_sockets[0], FUSE_OPENDIR, unique, 1, &open,
               sizeof(open), NULL, 0);
  close(failed_sockets[0]);
  wait_child(child);
  close(failed_cancellation[1]);

  int postreply_sockets[2];
  int postreply_cancellation[2];
  child = start_child(postreply_sockets, postreply_cancellation, 2);
  unique = 200;
  send_request(postreply_sockets[0], FUSE_INIT, unique, 0, &init, sizeof(init),
               NULL, 0);
  (void)receive_reply(postreply_sockets[0], unique++, reply,
                      sizeof(reply_storage.bytes));
  send_request(postreply_sockets[0], FUSE_OPENDIR, unique, 1, &open,
               sizeof(open), NULL, 0);
  (void)receive_reply(postreply_sockets[0], unique, reply,
                      sizeof(reply_storage.bytes));
  wait_child(child);
  close(postreply_sockets[0]);
  close(postreply_cancellation[1]);

  int fatal_sockets[2];
  int fatal_cancellation[2];
  child = start_child(fatal_sockets, fatal_cancellation, 3);
  unique = 300;
  send_request(fatal_sockets[0], FUSE_INIT, unique, 0, &init, sizeof(init),
               NULL, 0);
  (void)receive_reply(fatal_sockets[0], unique++, reply,
                      sizeof(reply_storage.bytes));
  send_request(fatal_sockets[0], FUSE_OPENDIR, unique, 1, &open, sizeof(open),
               NULL, 0);
  expect_error(fatal_sockets[0], unique, EIO);
  wait_child(child);
  close(fatal_sockets[0]);
  close(fatal_cancellation[1]);

  int fatal_postreply_sockets[2];
  int fatal_postreply_cancellation[2];
  child = start_child(fatal_postreply_sockets, fatal_postreply_cancellation, 4);
  unique = 400;
  send_request(fatal_postreply_sockets[0], FUSE_INIT, unique, 0, &init,
               sizeof(init), NULL, 0);
  (void)receive_reply(fatal_postreply_sockets[0], unique++, reply,
                      sizeof(reply_storage.bytes));
  send_request(fatal_postreply_sockets[0], FUSE_OPENDIR, unique, 1, &open,
               sizeof(open), NULL, 0);
  (void)receive_reply(fatal_postreply_sockets[0], unique, reply,
                      sizeof(reply_storage.bytes));
  wait_child(child);
  close(fatal_postreply_sockets[0]);
  close(fatal_postreply_cancellation[1]);

  int batch_sockets[2];
  int batch_cancellation[2];
  child = start_child(batch_sockets, batch_cancellation, 5);
  unique = 500;
  send_request(batch_sockets[0], FUSE_INIT, unique, 0, &init, sizeof(init),
               NULL, 0);
  (void)receive_reply(batch_sockets[0], unique++, reply,
                      sizeof(reply_storage.bytes));
  struct fuse_batch_forget_in batch = {.count = 2};
  struct fuse_forget_one forgotten[2] = {
      {.nodeid = 2, .nlookup = 1}, {.nodeid = 3, .nlookup = 1}};
  send_request(batch_sockets[0], FUSE_BATCH_FORGET, unique, 0, &batch,
               sizeof(batch), forgotten, sizeof(forgotten));
  wait_child(child);
  close(batch_sockets[0]);
  close(batch_cancellation[1]);

  for (int cookie_mode = 6; cookie_mode <= 8; ++cookie_mode) {
    int cookie_sockets[2];
    int cookie_cancellation[2];
    child = start_child(cookie_sockets, cookie_cancellation, cookie_mode);
    unique = (uint64_t)(600 + cookie_mode * 10);
    send_request(cookie_sockets[0], FUSE_INIT, unique, 0, &init, sizeof(init),
                 NULL, 0);
    (void)receive_reply(cookie_sockets[0], unique++, reply,
                        sizeof(reply_storage.bytes));
    send_request(cookie_sockets[0], FUSE_OPENDIR, unique, 1, &open,
                 sizeof(open), NULL, 0);
    (void)receive_reply(cookie_sockets[0], unique++, reply,
                        sizeof(reply_storage.bytes));
    send_request(cookie_sockets[0], FUSE_READDIR, unique, 1, &read,
                 sizeof(read), NULL, 0);
    expect_error(cookie_sockets[0], unique++, EIO);
    send_request(cookie_sockets[0], FUSE_GETATTR, unique, 1, &getattr,
                 sizeof(getattr), NULL, 0);
    wait_child(child);
    close(cookie_cancellation[1]);
    close(cookie_sockets[0]);
  }

  for (int attribute_mode = 9; attribute_mode <= 11; ++attribute_mode) {
    int attribute_sockets[2];
    int attribute_cancellation[2];
    child = start_child(attribute_sockets, attribute_cancellation,
                        attribute_mode);
    unique = (uint64_t)(700 + attribute_mode * 10);
    send_request(attribute_sockets[0], FUSE_INIT, unique, 0, &init,
                 sizeof(init), NULL, 0);
    (void)receive_reply(attribute_sockets[0], unique++, reply,
                        sizeof(reply_storage.bytes));
    if (attribute_mode == 10) {
      send_request(attribute_sockets[0], FUSE_GETATTR, unique, 1, &getattr,
                   sizeof(getattr), NULL, 0);
      send_request(attribute_sockets[0], FUSE_LOOKUP, unique + 1, 1, NULL, 0,
                   "child", 6);
    } else {
      send_request(attribute_sockets[0], FUSE_LOOKUP, unique, 1, NULL, 0,
                   "child", 6);
      send_request(attribute_sockets[0], FUSE_GETATTR, unique + 1, 1, &getattr,
                   sizeof(getattr), NULL, 0);
    }
    expect_error(attribute_sockets[0], unique, EIO);
    wait_child(child);
    close(attribute_cancellation[1]);
    close(attribute_sockets[0]);
  }

  int missing_reply_sockets[2];
  int missing_reply_cancellation[2];
  child = start_child(missing_reply_sockets, missing_reply_cancellation, 12);
  unique = 900;
  send_request(missing_reply_sockets[0], FUSE_INIT, unique, 0, &init,
               sizeof(init), NULL, 0);
  (void)receive_reply(missing_reply_sockets[0], unique++, reply,
                      sizeof(reply_storage.bytes));
  send_request(missing_reply_sockets[0], FUSE_OPENDIR, unique, 1, &open,
               sizeof(open), NULL, 0);
  send_request(missing_reply_sockets[0], FUSE_GETATTR, unique + 1, 1, &getattr,
               sizeof(getattr), NULL, 0);
  expect_error(missing_reply_sockets[0], unique, EIO);
  wait_child(child);
  close(missing_reply_cancellation[1]);
  close(missing_reply_sockets[0]);
  puts("aos-fuse-transport fake core and ABI 7.45 wire conformance passed");
  return 0;
}
