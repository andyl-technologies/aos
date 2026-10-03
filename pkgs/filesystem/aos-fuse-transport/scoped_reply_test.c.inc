/* SPDX-License-Identifier: Apache-2.0 */
/* Trusted custom-FD mechanics only: this fixture creates no ConsumerRead,
 * Root/Mount guard, backing admission or genuine kernel INIT/idmap proof. */

enum scoped_case {
  SCOPED_CASE_SUCCESS,
  SCOPED_CASE_MISSING_PUBLISH,
  SCOPED_CASE_DOUBLE_PUBLISH,
  SCOPED_CASE_SETTLEMENT_FAILURE,
  SCOPED_CASE_EXPIRED_OWNER,
  SCOPED_CASE_WRITE_CHECK_FAILURE,
  SCOPED_CASE_EXTENDED_OWNER,
  SCOPED_CASE_BLOCKED_TIMEOUT,
  SCOPED_CASE_BLOCKED_CANCELLATION,
  SCOPED_CASE_SLOW_CHECK_EXPIRY,
  SCOPED_CASE_SLOW_CHECK_CANCELLATION,
  SCOPED_CASE_PREPUBLICATION_FAILURE,
  SCOPED_CASE_COUNT
};

struct scoped_fake_core {
  struct fake_core legacy;
  enum scoped_case mode;
  unsigned settled;
  unsigned checks;
  int notice;
};

struct fake_scoped_borrow {
  bool held;
  enum scoped_case mode;
  unsigned *checks;
  int notice;
};

static int check_fake_scoped_borrow(const void *opaque) {
  const struct fake_scoped_borrow *borrow = opaque;
  if (!borrow->held)
    return EIO;
  (*borrow->checks)++;
  if ((borrow->mode == SCOPED_CASE_SLOW_CHECK_EXPIRY ||
       borrow->mode == SCOPED_CASE_SLOW_CHECK_CANCELLATION) &&
      *borrow->checks == 3) {
    if (borrow->mode == SCOPED_CASE_SLOW_CHECK_CANCELLATION &&
        write(borrow->notice, "r", 1) != 1)
      return EIO;
    struct timespec delay = {.tv_nsec = 200000000L};
    while (nanosleep(&delay, &delay) != 0)
      if (errno != EINTR)
        return EIO;
  }
  if ((borrow->mode == SCOPED_CASE_WRITE_CHECK_FAILURE &&
       *borrow->checks >= 3) ||
      borrow->mode == SCOPED_CASE_PREPUBLICATION_FAILURE)
    return ESTALE;
  return 0;
}

static int publish_fake_scoped(struct scoped_fake_core *core, uint64_t deadline,
                               struct aos_fuse_reply_scope_v3 *scope,
                               aos_fuse_publish_v3_fn publish, int error) {
  if (core->mode == SCOPED_CASE_MISSING_PUBLISH)
    return 0;
  struct timespec now;
  if (clock_gettime(CLOCK_BOOTTIME, &now) != 0)
    return AOS_FUSE_CORE_FATAL;
  uint64_t now_ns =
      (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
  uint64_t cutoff = deadline;
  if (core->mode == SCOPED_CASE_EXPIRED_OWNER)
    cutoff = now_ns;
  if (core->mode == SCOPED_CASE_EXTENDED_OWNER)
    cutoff = deadline + 1;
  if (core->mode == SCOPED_CASE_BLOCKED_TIMEOUT ||
      core->mode == SCOPED_CASE_SLOW_CHECK_EXPIRY)
    cutoff = now_ns + UINT64_C(100000000);
  /* Checker telemetry is independent stack storage, not an alias into the
   * callback's mutable context. Future Rust adapters must preserve this split.
   */
  unsigned checks = 0;
  struct fake_scoped_borrow borrow = {.held = true,
                                      .mode = core->mode,
                                      .checks = &checks,
                                      .notice = core->notice};
  if (core->mode == SCOPED_CASE_BLOCKED_CANCELLATION &&
      write(core->notice, "r", 1) != 1)
    return AOS_FUSE_CORE_FATAL;
  int result = publish(scope, cutoff, &borrow, check_fake_scoped_borrow, error);
  /* Completion observes the publication result before ending this borrow. */
  if (result == 0)
    core->settled++;
  if (core->mode == SCOPED_CASE_DOUBLE_PUBLISH) {
    if (result != 0 ||
        publish(scope, cutoff, &borrow, check_fake_scoped_borrow, error) != EIO)
      return AOS_FUSE_CORE_FATAL;
  }
  core->checks += checks;
  borrow.held = false;
  return core->mode == SCOPED_CASE_SETTLEMENT_FAILURE ? AOS_FUSE_CORE_FATAL
                                                      : result;
}

static int fake_scoped_lookup(void *opaque, uint64_t parent,
                              const uint8_t *name, uint64_t length,
                              struct aos_fuse_attributes *out,
                              uint64_t deadline,
                              struct aos_fuse_reply_scope_v3 *scope,
                              aos_fuse_publish_v3_fn publish) {
  struct scoped_fake_core *core = opaque;
  int error = core_lookup(&core->legacy, parent, name, length, out);
  return publish_fake_scoped(core, deadline, scope, publish, error);
}

static int fake_scoped_getattr(void *opaque, uint64_t node,
                               struct aos_fuse_attributes *out,
                               uint64_t deadline,
                               struct aos_fuse_reply_scope_v3 *scope,
                               aos_fuse_publish_v3_fn publish) {
  struct scoped_fake_core *core = opaque;
  int error = core_getattr(&core->legacy, node, out);
  return publish_fake_scoped(core, deadline, scope, publish, error);
}

static int fake_scoped_readlink(void *opaque, uint64_t node, uint8_t *target,
                                uint64_t capacity, uint64_t *length,
                                uint64_t deadline,
                                struct aos_fuse_reply_scope_v3 *scope,
                                aos_fuse_publish_v3_fn publish) {
  struct scoped_fake_core *core = opaque;
  int error = core_readlink(&core->legacy, node, target, capacity, length);
  return publish_fake_scoped(core, deadline, scope, publish, error);
}

static int fake_scoped_readdir(void *opaque, uint64_t node, uint64_t handle,
                               uint64_t cookie, uint64_t maximum_output,
                               struct aos_fuse_directory_entry *entries,
                               uint64_t capacity, uint64_t *count,
                               uint8_t *names, uint64_t names_capacity,
                               uint64_t *names_length, uint64_t deadline,
                               struct aos_fuse_reply_scope_v3 *scope,
                               aos_fuse_publish_v3_fn publish) {
  struct scoped_fake_core *core = opaque;
  int error =
      core_readdir(&core->legacy, node, handle, cookie, maximum_output, entries,
                   capacity, count, names, names_capacity, names_length);
  return publish_fake_scoped(core, deadline, scope, publish, error);
}

static int fake_scoped_read(void *opaque, uint64_t node, uint64_t handle,
                            int64_t offset, uint32_t size, uint64_t deadline,
                            uint8_t *output, uint64_t capacity,
                            uint64_t *length,
                            struct aos_fuse_reply_scope_v3 *scope,
                            aos_fuse_publish_v3_fn publish) {
  struct scoped_fake_core *core = opaque;
  int error = core_file_read(&core->legacy, node, handle, offset, size,
                             deadline, output, capacity, length);
  return publish_fake_scoped(core, deadline, scope, publish, error);
}

static struct aos_fuse_scoped_operations_v3 scoped_operations(void) {
  struct aos_fuse_scoped_operations_v3 result = {
      .abi_major = 3,
      .abi_minor = 0,
      .struct_size = sizeof(result),
      .profile = AOS_FUSE_PROFILE_SCOPED_REPLY,
      .lookup = fake_scoped_lookup,
      .getattr = fake_scoped_getattr,
      .readlink = fake_scoped_readlink,
      .readdir = fake_scoped_readdir,
      .read = fake_scoped_read,
  };
  result.legacy = fallback_operations();
  return result;
}

static int expected_scoped_error(enum scoped_case mode) {
  switch (mode) {
  case SCOPED_CASE_SUCCESS:
  case SCOPED_CASE_BLOCKED_CANCELLATION:
  case SCOPED_CASE_SLOW_CHECK_CANCELLATION:
    return ECANCELED;
  case SCOPED_CASE_EXPIRED_OWNER:
  case SCOPED_CASE_BLOCKED_TIMEOUT:
  case SCOPED_CASE_SLOW_CHECK_EXPIRY:
    return ETIMEDOUT;
  case SCOPED_CASE_WRITE_CHECK_FAILURE:
  case SCOPED_CASE_PREPUBLICATION_FAILURE:
    return ESTALE;
  case SCOPED_CASE_EXTENDED_OWNER:
  case SCOPED_CASE_COUNT:
    return EINVAL;
  case SCOPED_CASE_MISSING_PUBLISH:
  case SCOPED_CASE_DOUBLE_PUBLISH:
  case SCOPED_CASE_SETTLEMENT_FAILURE:
    return EIO;
  }
  return EINVAL;
}

static void scoped_reply_case(enum scoped_case mode) {
  int sockets[2];
  int cancellation[2];
  int notice[2];
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                 sockets) != 0 ||
      pipe2(cancellation, O_CLOEXEC | O_NONBLOCK) != 0 ||
      pipe2(notice, O_CLOEXEC) != 0)
    fail("scoped fixture descriptors failed");
  pid_t child = fork();
  if (child < 0)
    fail("scoped fixture fork failed");
  if (child == 0) {
    signal(SIGPIPE, SIG_IGN);
    close(sockets[0]);
    close(cancellation[1]);
    close(notice[0]);
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0)
      _exit(2);
    struct aos_fuse_preparation_v1 preparation = {
        .struct_size = sizeof(preparation),
        .abi_major = 1,
        .deadline_boottime_ns = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                                (uint64_t)now.tv_nsec + UINT64_C(2000000000),
        .limits = limits,
    };
    struct aos_fuse_prepared_session_v1 *prepared = NULL;
    if (aos_fuse_transport_prepare_test_fd_v1(sockets[1], cancellation[0],
                                              &preparation, &prepared) != 0)
      _exit(2);
    struct scoped_fake_core core = {.mode = mode, .notice = notice[1]};
    struct aos_fuse_scoped_operations_v3 ops = scoped_operations();
    /* Rejected attachment must leave the same prepared object idle. */
    struct aos_fuse_scoped_operations_v3 bad = ops;
    bad.read = NULL;
    if (aos_fuse_transport_continue_prepared_v3(prepared, &bad, &core) !=
            EINVAL ||
        core.legacy.destroy != 0 || core.legacy.getattr != 0)
      _exit(2);
    if (mode == SCOPED_CASE_BLOCKED_TIMEOUT ||
        mode == SCOPED_CASE_BLOCKED_CANCELLATION) {
      /* Fill this exact original send queue; publication must wait while the
       * callback's stack borrow stays held. No kernel-proof credit is claimed.
       */
      int send_buffer = 4096;
      if (setsockopt(sockets[1], SOL_SOCKET, SO_SNDBUF, &send_buffer,
                     sizeof(send_buffer)) != 0)
        _exit(2);
      while (send(sockets[1], "private-fixture-fill", 20, MSG_NOSIGNAL) >= 0) {
      }
      if (errno != EAGAIN && errno != EWOULDBLOCK)
        _exit(2);
    }
    if (write(notice[1], "p", 1) != 1)
      _exit(2);
    int result = aos_fuse_transport_continue_prepared_v3(prepared, &ops, &core);
    int valid =
        result == expected_scoped_error(mode) && core.legacy.destroy == 1 &&
        aos_fuse_transport_continue_prepared_v3(prepared, &ops, &core) ==
            EINVAL &&
        aos_fuse_transport_continue_prepared_v1(prepared, &operations, &core) ==
            EINVAL &&
        fcntl(sockets[1], F_GETFD) >= 0 && fcntl(cancellation[0], F_GETFD) >= 0;
    if (mode == SCOPED_CASE_SUCCESS)
      valid = valid && core.settled == 6 && core.checks >= 18 &&
              core.legacy.lookup == 2 && core.legacy.getattr == 1 &&
              core.legacy.readlink == 1 && core.legacy.readdir == 1 &&
              core.legacy.file_read == 1;
    else
      valid = valid && core.settled == ((mode == SCOPED_CASE_DOUBLE_PUBLISH ||
                                         mode == SCOPED_CASE_SETTLEMENT_FAILURE)
                                            ? 1U
                                            : 0U);
    if (mode == SCOPED_CASE_BLOCKED_TIMEOUT ||
        mode == SCOPED_CASE_BLOCKED_CANCELLATION)
      valid =
          valid && core.legacy.file_read == 1 &&
          core.checks >= (mode == SCOPED_CASE_BLOCKED_CANCELLATION ? 1U : 2U);
    if (mode == SCOPED_CASE_SLOW_CHECK_EXPIRY ||
        mode == SCOPED_CASE_SLOW_CHECK_CANCELLATION)
      valid = valid && core.checks >= 3;
    aos_fuse_transport_destroy_prepared_v1(prepared);
    _exit(valid && core.legacy.destroy == 1 ? 0 : 2);
  }
  close(sockets[1]);
  close(cancellation[0]);
  close(notice[1]);
  struct fuse_init_in init = {
      .major = 7,
      .minor = 45,
      .flags = FUSE_INIT_EXT | FUSE_MAX_PAGES,
      .flags2 = (uint32_t)((FUSE_ALLOW_IDMAP | FUSE_REQUEST_TIMEOUT) >> 32),
  };
  send_request(sockets[0], FUSE_INIT, 201, 0, &init, sizeof(init), NULL, 0);
  static union aligned_buffer reply;
  (void)receive_reply(sockets[0], 201, reply.bytes, sizeof(reply.bytes));
  struct pollfd ready = {.fd = notice[0], .events = POLLIN};
  char byte;
  if (poll(&ready, 1, DEADLINE_MS) != 1 || read(notice[0], &byte, 1) != 1 ||
      byte != 'p')
    fail("same prepared scoped session was not retained");
  struct fuse_getattr_in getattr = {0};
  if (mode == SCOPED_CASE_BLOCKED_TIMEOUT ||
      mode == SCOPED_CASE_BLOCKED_CANCELLATION) {
    struct fuse_read_in read_request = {.fh = 91, .size = 3};
    send_request(sockets[0], FUSE_READ, 202, 2, &read_request,
                 sizeof(read_request), NULL, 0);
    if (mode == SCOPED_CASE_BLOCKED_CANCELLATION) {
      if (poll(&ready, 1, DEADLINE_MS) != 1 || read(notice[0], &byte, 1) != 1 ||
          byte != 'r')
        fail("scoped cancellation did not reach held publication");
      if (write(cancellation[1], "x", 1) != 1)
        fail("scoped cancellation failed");
    }
    wait_child(child);
    /* Only the deliberate filler may be observable after the failed write. */
    ssize_t amount;
    while ((amount = recv(sockets[0], reply.bytes, sizeof(reply.bytes), 0)) > 0)
      if (amount != 20 || memcmp(reply.bytes, "private-fixture-fill", 20) != 0)
        fail("failed scoped publication exposed a reply body");
  } else {
    send_request(sockets[0], FUSE_GETATTR, 202, 1, &getattr, sizeof(getattr),
                 NULL, 0);
    if (mode == SCOPED_CASE_SLOW_CHECK_CANCELLATION) {
      if (poll(&ready, 1, DEADLINE_MS) != 1 || read(notice[0], &byte, 1) != 1 ||
          byte != 'r' || write(cancellation[1], "x", 1) != 1)
        fail("scoped cancellation during check failed");
    }
    if (mode != SCOPED_CASE_EXPIRED_OWNER &&
        mode != SCOPED_CASE_WRITE_CHECK_FAILURE &&
        mode != SCOPED_CASE_SLOW_CHECK_EXPIRY &&
        mode != SCOPED_CASE_SLOW_CHECK_CANCELLATION) {
      size_t length =
          receive_reply(sockets[0], 202, reply.bytes, sizeof(reply.bytes));
      struct fuse_out_header *header = (struct fuse_out_header *)reply.bytes;
      bool published = mode == SCOPED_CASE_SUCCESS ||
                       mode == SCOPED_CASE_DOUBLE_PUBLISH ||
                       mode == SCOPED_CASE_SETTLEMENT_FAILURE;
      int denied_error = mode == SCOPED_CASE_EXTENDED_OWNER           ? EINVAL
                         : mode == SCOPED_CASE_PREPUBLICATION_FAILURE ? ESTALE
                                                                      : EIO;
      if (header->error != (published ? 0 : -denied_error) ||
          length !=
              sizeof(*header) + (published ? sizeof(struct fuse_attr_out) : 0))
        fail("scoped publication result mismatch");
    }
    if (mode == SCOPED_CASE_SUCCESS) {
      send_request(sockets[0], FUSE_LOOKUP, 203, 1, NULL, 0, "child", 6);
      size_t length =
          receive_reply(sockets[0], 203, reply.bytes, sizeof(reply.bytes));
      if (length !=
          sizeof(struct fuse_out_header) + sizeof(struct fuse_entry_out))
        fail("scoped lookup body mismatch");
      send_request(sockets[0], FUSE_LOOKUP, 204, 1, NULL, 0, "missing", 8);
      (void)receive_reply(sockets[0], 204, reply.bytes, sizeof(reply.bytes));
      if (((struct fuse_entry_out *)(reply.bytes +
                                     sizeof(struct fuse_out_header)))
              ->nodeid != 0)
        fail("scoped negative lookup changed legacy semantics");
      send_request(sockets[0], FUSE_READLINK, 205, 3, NULL, 0, NULL, 0);
      length = receive_reply(sockets[0], 205, reply.bytes, sizeof(reply.bytes));
      if (length != sizeof(struct fuse_out_header) + 6 ||
          memcmp(reply.bytes + sizeof(struct fuse_out_header), "target", 6) !=
              0)
        fail("scoped readlink body mismatch");
      struct fuse_read_in directory = {.fh = 77, .size = 4096};
      send_request(sockets[0], FUSE_READDIR, 206, 1, &directory,
                   sizeof(directory), NULL, 0);
      length = receive_reply(sockets[0], 206, reply.bytes, sizeof(reply.bytes));
      if (length <= sizeof(struct fuse_out_header))
        fail("scoped directory reply was empty");
      struct fuse_read_in read = {.fh = 91, .size = 3};
      send_request(sockets[0], FUSE_READ, 207, 2, &read, sizeof(read), NULL, 0);
      length = receive_reply(sockets[0], 207, reply.bytes, sizeof(reply.bytes));
      if (length != sizeof(struct fuse_out_header) + 3 ||
          memcmp(reply.bytes + sizeof(struct fuse_out_header), "abc", 3) != 0)
        fail("scoped READ body mismatch");
      close(cancellation[1]);
    }
    wait_child(child);
    struct pollfd no_second = {.fd = sockets[0], .events = POLLIN};
    if (poll(&no_second, 1, 0) > 0 &&
        recv(sockets[0], reply.bytes, sizeof(reply.bytes), 0) > 0)
      fail("scoped callback failure published a second reply");
  }
  if (mode != SCOPED_CASE_SUCCESS)
    close(cancellation[1]);
  close(sockets[0]);
  close(notice[0]);
}

static void test_scoped_reply_v3(void) {
  if (sizeof(struct aos_fuse_scoped_operations_v3) != 192 ||
      offsetof(struct aos_fuse_scoped_operations_v3, legacy) != 16 ||
      offsetof(struct aos_fuse_scoped_operations_v3, lookup) != 152)
    fail("scoped ABI changed its explicit legacy embedding");
  for (unsigned mode = 0; mode < SCOPED_CASE_COUNT; mode++)
    scoped_reply_case((enum scoped_case)mode);
}
