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

/* Valid only during one scoped OPEN/OPENDIR callback, callable exactly once. */
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

#define AOS_FUSE_FALLBACK_ABI_MAJOR 2U
#define AOS_FUSE_FALLBACK_ABI_MINOR 0U
#define AOS_FUSE_PROFILE_BOUNDED_FALLBACK 1U

/*
 * V2 deliberately embeds the unchanged V1 metadata contract. Both outer
 * headers must name exactly the bounded-fallback profile. No passthrough,
 * xattrs, ACL or sparse-allocation/SEEK_HOLE profile is negotiated here.
 * deadline_ns is captured from CLOCK_BOOTTIME before core work and remains
 * the same absolute bound through publication. Read output is private C
 * staging; only a successful callback's exact length may become a reply.
 * A failed OPEN publication is ambiguous, not definite rollback: the core
 * must retain the pending pin until terminal teardown. Regular-file replies
 * use direct I/O and never export an immutable backing descriptor to libfuse.
 */
struct aos_fuse_fallback_operations_v2 {
  uint16_t abi_major;
  uint16_t abi_minor;
  uint32_t struct_size;
  uint32_t profile;
  uint32_t reserved;
  struct aos_fuse_core_operations metadata;
  int (*open)(void *context, uint64_t node_id, int32_t flags,
              uint64_t deadline_ns, struct aos_fuse_open_responder *responder,
              aos_fuse_reply_open_fn reply_open);
  int (*read)(void *context, uint64_t node_id, uint64_t handle, int64_t offset,
              uint32_t size, uint64_t deadline_ns, uint8_t *output,
              uint64_t output_capacity, uint64_t *output_length);
  int (*release)(void *context, uint64_t node_id, uint64_t handle,
                 int32_t flags, uint32_t release_flags, uint64_t lock_owner,
                 uint64_t deadline_ns);
};

struct aos_fuse_fallback_limits_v2 {
  uint16_t abi_major;
  uint16_t abi_minor;
  uint32_t struct_size;
  uint32_t profile;
  uint32_t reserved;
  struct aos_fuse_limits metadata;
};

/* Dormant transport candidate, not mount or backing-disclosure authority. */
int aos_fuse_transport_run_fallback_v2(
    int connected_fd, int cancellation_fd,
    const struct aos_fuse_fallback_operations_v2 *operations,
    void *core_context, const struct aos_fuse_fallback_limits_v2 *limits);

/* Additive private reply-scoped profile; existing V1/V2 layouts stay exact. */
#define AOS_FUSE_SCOPED_ABI_MAJOR 3U
#define AOS_FUSE_SCOPED_ABI_MINOR 0U
#define AOS_FUSE_PROFILE_SCOPED_REPLY 1U

struct aos_fuse_reply_scope_v3;

/* A synchronous read-only check of the caller's separately retained borrow.
 * Its context must NOT alias a mutably borrowed callback context. It must not
 * unwind, publish a reply or retain any pointer; zero permits this attempt. */
typedef int (*aos_fuse_scope_check_v3_fn)(const void *held_context);

/* Callable once, only on the callback stack. The absolute owner cutoff may
 * only shorten the C request deadline. The guard/check borrow survives every
 * blocked write and is forgotten before return. Zero reports one complete
 * kernel reply write, not consumer consumption or durable settlement. Any
 * attempted failure is ambiguous and terminal; no second reply is permitted.
 * error is zero for the prepared output or a positive errno for denial. */
typedef int (*aos_fuse_publish_v3_fn)(
    struct aos_fuse_reply_scope_v3 *scope, uint64_t owner_deadline_ns,
    const void *held_context, aos_fuse_scope_check_v3_fn check, int error);

/* The unchanged V2 table supplies OPEN/OPENDIR and cleanup only. All five
 * disclosure callbacks below are mandatory overrides; returning success
 * without invoking publish exactly once is an integrity failure. The caller
 * holds its genuine original authority through publish and subsequent
 * settlement, returning FATAL if settlement is uncertain after publication.
 * This process-local table/check is transport mechanics, never a read grant. */
struct aos_fuse_scoped_operations_v3 {
  uint16_t abi_major;
  uint16_t abi_minor;
  uint32_t struct_size;
  uint32_t profile;
  uint32_t reserved;
  struct aos_fuse_fallback_operations_v2 legacy;
  int (*lookup)(void *context, uint64_t parent, const uint8_t *name,
                uint64_t name_length, struct aos_fuse_attributes *attributes,
                uint64_t deadline_ns, struct aos_fuse_reply_scope_v3 *scope,
                aos_fuse_publish_v3_fn publish);
  int (*getattr)(void *context, uint64_t node_id,
                 struct aos_fuse_attributes *attributes, uint64_t deadline_ns,
                 struct aos_fuse_reply_scope_v3 *scope,
                 aos_fuse_publish_v3_fn publish);
  int (*readlink)(void *context, uint64_t node_id, uint8_t *target,
                  uint64_t capacity, uint64_t *length, uint64_t deadline_ns,
                  struct aos_fuse_reply_scope_v3 *scope,
                  aos_fuse_publish_v3_fn publish);
  int (*readdir)(void *context, uint64_t node_id, uint64_t handle,
                 uint64_t cookie, uint64_t maximum_output_bytes,
                 struct aos_fuse_directory_entry *entries, uint64_t capacity,
                 uint64_t *count, uint8_t *names, uint64_t names_capacity,
                 uint64_t *names_length, uint64_t deadline_ns,
                 struct aos_fuse_reply_scope_v3 *scope,
                 aos_fuse_publish_v3_fn publish);
  int (*read)(void *context, uint64_t node_id, uint64_t handle, int64_t offset,
              uint32_t size, uint64_t deadline_ns, uint8_t *output,
              uint64_t capacity, uint64_t *length,
              struct aos_fuse_reply_scope_v3 *scope,
              aos_fuse_publish_v3_fn publish);
};

/* Additive private in-process lifecycle; no pointer crosses a process protocol.
 * The old ABI and run entry remain unchanged. These objects prove transport
 * preparation only, never Mount/Root authority, attachment or content access. */
#define AOS_FUSE_PREPARED_SESSION_ABI_MAJOR 1U
#define AOS_FUSE_PREPARED_SESSION_ABI_MINOR 0U

struct aos_fuse_preparation_v1 {
  uint32_t struct_size;
  uint16_t abi_major;
  uint16_t abi_minor;
  uint32_t flags;
  uint32_t reserved;
  uint64_t deadline_boottime_ns;
  struct aos_fuse_limits limits;
};

struct aos_fuse_prepared_session_v1;

/* Borrows the original nonblocking /dev/fuse OFD and cancellation reader.
 * Reads exactly one genuine kernel INIT, requires 7.45 and ALLOW_IDMAP, and
 * retains the SAME libfuse session after its complete successful INIT reply.
 * No metadata/core callback runs during preparation. The caller retains both
 * originals until destroy, and Mount retains/applies its actual namespace
 * idmap separately. Failure leaves *prepared NULL; it never adopts an already
 * initialized connection or reconstructs a session from a receipt. */
int aos_fuse_transport_prepare_v1(
    int connected_fd, int cancellation_fd,
    const struct aos_fuse_preparation_v1 *preparation,
    struct aos_fuse_prepared_session_v1 **prepared);

/* Continues the original session exactly once, without another INIT. This
 * private unsafe ABI attaches only a synchronous borrowed callback context;
 * the trusted caller MUST already retain genuine current Root+Mount authority
 * and actual idmap/backing owner joins through dispatch. Neither the prepared
 * pointer, callback table, plan nor a boolean supplies that authority. No safe
 * public adapter is installed until those real producers are joined. The
 * caller must destroy the session after terminal return, including failure. */
int aos_fuse_transport_continue_prepared_v1(
    struct aos_fuse_prepared_session_v1 *prepared,
    const struct aos_fuse_core_operations *operations, void *core_context);

/* Attaches the reply-scoped profile to the SAME prepared session once. Bounded
 * READ staging is allocated before any callback/context is attached. Failed
 * admission leaves preparation idle; terminal dispatch ends the borrow and
 * destroys only this session's duplicate, as in continue_prepared_v1.
 * This unsafe private entry has NO installed safe Rust authority adapter. */
int aos_fuse_transport_continue_prepared_v3(
    struct aos_fuse_prepared_session_v1 *prepared,
    const struct aos_fuse_scoped_operations_v3 *operations, void *core_context);

/* Destroys exactly the same retained session and closes only its duplicate
 * FUSE descriptor. NULL is accepted; every non-NULL pointer must be the sole
 * live result of prepare_v1 and must be passed exactly once. */
void aos_fuse_transport_destroy_prepared_v1(
    struct aos_fuse_prepared_session_v1 *prepared);

#ifdef AOS_FUSE_TRANSPORT_TESTING
/* Test-only socket/pipe entry; never exported by the installed library. */
int aos_fuse_transport_run_test_fd(
    int connected_fd, int cancellation_fd,
    const struct aos_fuse_core_operations *operations,
    void *core_context, const struct aos_fuse_limits *limits);
int aos_fuse_transport_run_fallback_v2_test_fd(
    int connected_fd, int cancellation_fd,
    const struct aos_fuse_fallback_operations_v2 *operations,
    void *core_context, const struct aos_fuse_fallback_limits_v2 *limits);
/* Same lifecycle over trusted fake transport, never an installed FD adopter. */
int aos_fuse_transport_prepare_test_fd_v1(
    int connected_fd, int cancellation_fd,
    const struct aos_fuse_preparation_v1 *preparation,
    struct aos_fuse_prepared_session_v1 **prepared);
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
