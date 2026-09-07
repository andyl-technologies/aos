/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AOS_FUSE_TRANSPORT_H
#define AOS_FUSE_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AOS_FUSE_TRANSPORT_ABI_MAJOR 1U
#define AOS_FUSE_TRANSPORT_ABI_MINOR 0U
#define AOS_FUSE_KIND_FILE 1U
#define AOS_FUSE_KIND_DIRECTORY 2U
#define AOS_FUSE_KIND_SYMLINK 3U
#define AOS_FUSE_CORE_FATAL (-1)

struct aos_fuse_attributes {
  uint64_t node_id;
  uint64_t size;
  int64_t mtime_seconds;
  uint32_t mtime_nanos;
  uint32_t uid;
  uint32_t gid;
  uint32_t nlink;
  uint16_t mode;
  uint8_t kind;
  uint8_t reserved;
};

struct aos_fuse_directory_entry {
  /* Zero means that the inode is deliberately unknown to the kernel. */
  uint64_t node_id;
  uint64_t next_cookie;
  uint32_t name_offset;
  uint16_t name_length;
  uint8_t kind;
  uint8_t reserved;
};

struct aos_fuse_limits {
  uint32_t struct_size;
  uint16_t abi_major;
  uint16_t abi_minor;
  uint32_t flags;
  uint32_t reserved0;
  uint32_t maximum_name_bytes;
  uint32_t maximum_symlink_bytes;
  uint32_t maximum_readdir_bytes;
  uint32_t maximum_readdir_entries;
  uint32_t maximum_write_bytes;
  uint32_t maximum_pages;
  uint32_t time_granularity_ns;
  uint16_t request_timeout_seconds;
  uint16_t reserved1;
  uint64_t entry_valid_ns;
  uint64_t attribute_valid_ns;
};

struct aos_fuse_open_responder;

/* Valid only during one opendir callback and callable exactly once. */
typedef int (*aos_fuse_reply_open_fn)(struct aos_fuse_open_responder *responder,
                                      uint64_t handle);

/*
 * All callbacks are synchronous. The bridge retains neither callback inputs
 * nor outputs and the core must not retain their borrowed pointers. Return
 * zero for success or a positive errno. Negative and unknown errors become
 * EIO. The bridge is the sole owner of fuse_reply_* calls. Interrupt state is
 * sampled before dispatch; an in-progress callback is never preempted. The
 * core must itself return each callback within request_timeout_seconds.
 * A language adapter must catch unwinds before they cross this ABI (or use an
 * abort policy) and return AOS_FUSE_CORE_FATAL for integrity failure. Fatal
 * disposition terminates the session after at most one EIO reply.
 */
struct aos_fuse_core_operations {
  uint16_t abi_major;
  uint16_t abi_minor;
  uint32_t struct_size;
  uint32_t attributes_size;
  uint32_t directory_entry_size;
  uint32_t limits_size;
  uint32_t flags;
  uint32_t reserved;

  int (*lookup)(void *context, uint64_t parent, const uint8_t *name,
                uint64_t name_length, struct aos_fuse_attributes *attributes);
  int (*forget)(void *context, uint64_t node_id, uint64_t lookup_count);
  int (*getattr)(void *context, uint64_t node_id,
                 struct aos_fuse_attributes *attributes);
  int (*readlink)(void *context, uint64_t node_id, uint8_t *target,
                  uint64_t target_capacity, uint64_t *target_length);

  /*
   * The core keeps its pending reservation on the callback stack, invokes
   * reply_open, then commits only when reply_open returns zero. It aborts
   * before returning on every other path. Neither side retains responder.
   */
  int (*opendir)(void *context, uint64_t node_id,
                 struct aos_fuse_open_responder *responder,
                 aos_fuse_reply_open_fn reply_open);

  int (*readdir)(void *context, uint64_t node_id, uint64_t handle,
                 uint64_t cookie, uint64_t maximum_output_bytes,
                 struct aos_fuse_directory_entry *entries,
                 uint64_t entry_capacity, uint64_t *entry_count,
                 uint8_t *names, uint64_t names_capacity,
                 uint64_t *names_length);
  int (*releasedir)(void *context, uint64_t node_id, uint64_t handle);

  /* Notifies scoped teardown; ownership of context always remains with caller. */
  void (*destroy)(void *context);
};

/*
 * Runs one single-threaded session while borrowing connected_fd. The bridge
 * duplicates the descriptor and gives only that duplicate to libfuse; the
 * caller's original remains valid on every return path. The duplicate shares
 * the original open-file description and therefore its status flags.
 * Production entry requires a nonblocking, open read/write /dev/fuse
 * character device and a distinct nonblocking readable cancellation fd.
 * That descriptor cannot prove mount-time allow_other or default_permissions;
 * the broker and real-kernel gate remain responsible for those properties.
 * cancellation_fd is borrowed for the call and must become readable to request
 * teardown. Idle request reception waits indefinitely but remains cancellation
 * responsive; each reply write uses one absolute request_timeout_seconds
 * deadline across poll and retry.
 * The caller retains ownership of connected_fd and cancellation_fd.
 * Returns zero after an orderly session or a positive errno on failure.
 */
int aos_fuse_transport_run(int connected_fd, int cancellation_fd,
                           const struct aos_fuse_core_operations *operations,
                           void *core_context,
                           const struct aos_fuse_limits *limits);

#ifdef AOS_FUSE_TRANSPORT_TESTING
/* Test-only socket/pipe entry; never exported by the installed library. */
int aos_fuse_transport_run_test_fd(
    int connected_fd, int cancellation_fd,
    const struct aos_fuse_core_operations *operations,
    void *core_context, const struct aos_fuse_limits *limits);
/* Directly verifies record-write behavior; never exported by the library. */
int aos_fuse_transport_test_writev(int connected_fd, int cancellation_fd,
                                   const uint8_t *first, uint64_t first_length,
                                   const uint8_t *second,
                                   uint64_t second_length,
                                   uint16_t timeout_seconds,
                                   int *terminal_error);
#endif

#ifdef __cplusplus
}
#endif
#endif
