/* SPDX-License-Identifier: Apache-2.0 */
/* Private reply-scoped adapter for the owning transport.c translation unit.
 * A responder and its independent read-only check borrow stay on the callback
 * stack through real kernel publication. Neither is a consumer authority. */

enum scoped_reply_kind {
  SCOPED_LOOKUP,
  SCOPED_ATTRIBUTES,
  SCOPED_READLINK,
  SCOPED_DIRECTORY,
  SCOPED_READ
};

struct aos_fuse_reply_scope_v3 {
  struct aos_fuse_transport *transport;
  fuse_req_t request;
  enum scoped_reply_kind kind;
  uint64_t deadline_ns;
  struct aos_fuse_attributes attributes;
  uint64_t length;
  uint64_t count;
  uint64_t names_length;
  uint64_t cookie;
  size_t maximum_output;
  const void *held_context;
  aos_fuse_scope_check_v3_fn check;
  bool invoked;
  bool attempted;
  int result;
};

static int check_write_scope(struct aos_fuse_transport *transport) {
  struct aos_fuse_reply_scope_v3 *scope = transport->write_scope;
  if (scope == NULL)
    return 0;
  int error = interrupted(scope->request);
  if (error == 0)
    error = normalize_error(scope->check(scope->held_context));
  /* The owner check can block after readiness. Reobserve cancellation and
   * interruption without a new wait budget while this request is still live. */
  if (error == 0) {
    struct pollfd cancellation = {.fd = transport->cancellation_fd,
                                  .events = POLLIN};
    for (;;) {
      int remaining =
          remaining_milliseconds(transport, &transport->file_deadline);
      if (remaining < 0) {
        error = -remaining;
        break;
      }
      int ready = poll(&cancellation, 1, 0);
      if (ready < 0 && errno == EINTR)
        continue;
      if (ready < 0)
        error = errno;
      else if ((cancellation.revents &
                (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0)
        error = ECANCELED;
      break;
    }
  }
  if (error == 0)
    error = interrupted(scope->request);
  /* Time consumed by the check cannot renew the original cutoff. */
  if (error == 0) {
    int remaining =
        remaining_milliseconds(transport, &transport->file_deadline);
    if (remaining < 0)
      error = -remaining;
  }
  if (error != 0) {
    poison(transport, error);
    errno = error;
  }
  return error;
}

static int publish_scoped_once(struct aos_fuse_reply_scope_v3 *scope,
                               uint64_t owner_deadline_ns,
                               const void *held_context,
                               aos_fuse_scope_check_v3_fn check, int error) {
  if (scope == NULL)
    return EINVAL;
  struct aos_fuse_transport *transport = scope->transport;
  if (scope->invoked || transport->write_scope != NULL) {
    poison(transport, EIO);
    return EIO;
  }
  scope->invoked = true;
  if (check == NULL || held_context == NULL || owner_deadline_ns == 0 ||
      owner_deadline_ns > scope->deadline_ns || error < 0 ||
      normalize_error(error) != error) {
    poison(transport, EINVAL);
    return EINVAL;
  }

  /* The owner bound cannot renew the original request. begin_file_request
   * already proved representability of the larger original deadline. */
  transport->file_deadline.tv_sec =
      (time_t)(owner_deadline_ns / UINT64_C(1000000000));
  transport->file_deadline.tv_nsec =
      (long)(owner_deadline_ns % UINT64_C(1000000000));
  scope->held_context = held_context;
  scope->check = check;
  transport->write_scope = scope;
  if (remaining_milliseconds(transport, &transport->file_deadline) < 0 ||
      check_write_scope(transport) != 0) {
    scope->result = transport->terminal_error;
  } else {
    /* libfuse consumes the request on every reply attempt, including error.
     * No callback failure after this point may publish a second reply. */
    scope->attempted = true;
    if (error != 0 && !(scope->kind == SCOPED_LOOKUP && error == ENOENT)) {
      scope->result = publish_error(scope->request, error);
    } else {
      switch (scope->kind) {
      case SCOPED_LOOKUP:
        scope->result =
            publish_lookup(scope->request, error, &scope->attributes);
        break;
      case SCOPED_ATTRIBUTES:
        scope->result =
            publish_attributes(scope->request, 0, &scope->attributes);
        break;
      case SCOPED_READLINK:
        scope->result = publish_readlink(scope->request, 0, scope->length);
        break;
      case SCOPED_DIRECTORY:
        scope->result = publish_directory(scope->request, scope->cookie,
                                          scope->maximum_output, scope->count,
                                          scope->names_length);
        break;
      case SCOPED_READ:
        scope->result = publish_read(scope->request, 0, scope->length,
                                     scope->maximum_output);
        break;
      }
    }
  }
  /* Forget the borrowed checker before returning to the caller's settlement.
   * The caller still owns its guard; C must retain no Rust stack pointer. */
  transport->write_scope = NULL;
  scope->held_context = NULL;
  scope->check = NULL;
  return scope->result;
}

static int begin_scoped_reply(fuse_req_t request, enum scoped_reply_kind kind,
                              struct aos_fuse_reply_scope_v3 *scope) {
  memset(scope, 0, sizeof(*scope));
  scope->transport = transport_for(request);
  scope->request = request;
  scope->kind = kind;
  int error = begin_file_request(scope->transport, &scope->deadline_ns);
  return error == 0 ? interrupted(request) : error;
}

static void finish_scoped_reply(struct aos_fuse_reply_scope_v3 *scope,
                                int raw_error) {
  struct aos_fuse_transport *transport = scope->transport;
  bool fatal = false;
  int error = core_result(raw_error, &fatal);
  if (!scope->attempted) {
    if (error == 0)
      reply_integrity_failure(scope->request);
    else
      reply_error(scope->request, error);
  } else if (error != 0 || scope->result != 0) {
    poison(transport, error != 0 ? error : scope->result);
  }
  if (fatal)
    poison(transport, EIO);
  if (scope->kind == SCOPED_READ)
    memset(transport->read_output, 0, transport->limits.maximum_write_bytes);
  transport->file_deadline_active = false;
}

static void scoped_lookup(fuse_req_t request, fuse_ino_t parent,
                          const char *name) {
  struct aos_fuse_reply_scope_v3 scope;
  int error = begin_scoped_reply(request, SCOPED_LOOKUP, &scope);
  struct aos_fuse_transport *transport = scope.transport;
  size_t length = strnlen(name, transport->limits.maximum_name_bytes + 1U);
  if (error == 0 &&
      (length == 0 || length > transport->limits.maximum_name_bytes ||
       memchr(name, '/', length) != NULL))
    error =
        length > transport->limits.maximum_name_bytes ? ENAMETOOLONG : EINVAL;
  if (error == 0)
    error = transport->scoped->lookup(
        transport->core_context, parent, (const uint8_t *)name, length,
        &scope.attributes, scope.deadline_ns, &scope, publish_scoped_once);
  finish_scoped_reply(&scope, error);
}

static void scoped_getattr(fuse_req_t request, fuse_ino_t node) {
  struct aos_fuse_reply_scope_v3 scope;
  int error = begin_scoped_reply(request, SCOPED_ATTRIBUTES, &scope);
  if (error == 0)
    error = scope.transport->scoped->getattr(
        scope.transport->core_context, node, &scope.attributes,
        scope.deadline_ns, &scope, publish_scoped_once);
  finish_scoped_reply(&scope, error);
}

static void scoped_readlink(fuse_req_t request, fuse_ino_t node) {
  struct aos_fuse_reply_scope_v3 scope;
  int error = begin_scoped_reply(request, SCOPED_READLINK, &scope);
  struct aos_fuse_transport *transport = scope.transport;
  memset(transport->target, 0,
         (size_t)transport->limits.maximum_symlink_bytes + 1U);
  if (error == 0)
    error = transport->scoped->readlink(
        transport->core_context, node, transport->target,
        transport->limits.maximum_symlink_bytes, &scope.length,
        scope.deadline_ns, &scope, publish_scoped_once);
  finish_scoped_reply(&scope, error);
}

static void scoped_readdir(fuse_req_t request, fuse_ino_t node, size_t size,
                           off_t offset, struct fuse_file_info *file) {
  struct aos_fuse_reply_scope_v3 scope;
  int error = begin_scoped_reply(request, SCOPED_DIRECTORY, &scope);
  struct aos_fuse_transport *transport = scope.transport;
  if (error == 0 && offset < 0)
    error = EINVAL;
  scope.cookie = (uint64_t)offset;
  scope.maximum_output = size < transport->limits.maximum_readdir_bytes
                             ? size
                             : transport->limits.maximum_readdir_bytes;
  memset(transport->entries, 0,
         (size_t)transport->limits.maximum_readdir_entries *
             sizeof(*transport->entries));
  memset(transport->names, 0, transport->limits.maximum_readdir_bytes);
  memset(transport->name, 0, (size_t)transport->limits.maximum_name_bytes + 1U);
  memset(transport->directory_output, 0,
         transport->limits.maximum_readdir_bytes);
  if (error == 0)
    error = transport->scoped->readdir(
        transport->core_context, node, file->fh, scope.cookie,
        scope.maximum_output, transport->entries,
        transport->limits.maximum_readdir_entries, &scope.count,
        transport->names, transport->limits.maximum_readdir_bytes,
        &scope.names_length, scope.deadline_ns, &scope, publish_scoped_once);
  finish_scoped_reply(&scope, error);
}

static void scoped_read(fuse_req_t request, fuse_ino_t node, size_t size,
                        off_t offset, struct fuse_file_info *file) {
  struct aos_fuse_reply_scope_v3 scope;
  int error = begin_scoped_reply(request, SCOPED_READ, &scope);
  struct aos_fuse_transport *transport = scope.transport;
  if (error == 0 &&
      (offset < 0 || size > transport->limits.maximum_write_bytes))
    error = size > transport->limits.maximum_write_bytes ? ENOMEM : EINVAL;
  scope.maximum_output = size;
  if (error == 0)
    error = transport->scoped->read(transport->core_context, node, file->fh,
                                    (int64_t)offset, (uint32_t)size,
                                    scope.deadline_ns, transport->read_output,
                                    transport->limits.maximum_write_bytes,
                                    &scope.length, &scope, publish_scoped_once);
  finish_scoped_reply(&scope, error);
}

static int
validate_scoped_contract(const struct aos_fuse_scoped_operations_v3 *operations,
                         const struct aos_fuse_limits *limits) {
  if (operations == NULL ||
      operations->abi_major != AOS_FUSE_SCOPED_ABI_MAJOR ||
      operations->abi_minor != AOS_FUSE_SCOPED_ABI_MINOR ||
      operations->struct_size != sizeof(*operations) ||
      operations->profile != AOS_FUSE_PROFILE_SCOPED_REPLY ||
      operations->reserved != 0 || operations->lookup == NULL ||
      operations->getattr == NULL || operations->readlink == NULL ||
      operations->readdir == NULL || operations->read == NULL)
    return EINVAL;
  struct aos_fuse_fallback_limits_v2 legacy = {
      .abi_major = AOS_FUSE_FALLBACK_ABI_MAJOR,
      .abi_minor = AOS_FUSE_FALLBACK_ABI_MINOR,
      .struct_size = sizeof(legacy),
      .profile = AOS_FUSE_PROFILE_BOUNDED_FALLBACK,
      .metadata = *limits,
  };
  return validate_fallback_contract(&operations->legacy, &legacy);
}

int aos_fuse_transport_continue_prepared_v3(
    struct aos_fuse_prepared_session_v1 *prepared,
    const struct aos_fuse_scoped_operations_v3 *operations,
    void *core_context) {
  if (prepared == NULL)
    return EINVAL;
  struct aos_fuse_transport *transport = &prepared->transport;
  if (transport->phase != TRANSPORT_PREPARED || transport->session == NULL ||
      transport->terminal_error != 0 || fuse_session_exited(transport->session))
    return EINVAL;
  int error = validate_scoped_contract(operations, &transport->limits);
  if (error != 0)
    return error;
  uint8_t *read_output = calloc(transport->limits.maximum_write_bytes, 1);
  if (read_output == NULL)
    return ENOMEM;

  /* All admission/allocation precedes attachment. No new session, INIT or
   * OFD is created, and no callback owns a pointer after release returns. */
  transport->read_output = read_output;
  transport->operations = &operations->legacy.metadata;
  transport->fallback = &operations->legacy;
  transport->scoped = operations;
  transport->core_context = core_context;
  transport->phase = TRANSPORT_CONTINUING;
  error = fuse_session_loop(transport->session) == 0 ? 0 : EIO;
  if (transport->terminal_error != 0)
    error = transport->terminal_error;
  release_transport(transport);
  transport->operations = NULL;
  transport->fallback = NULL;
  transport->scoped = NULL;
  transport->core_context = NULL;
  transport->phase = TRANSPORT_FINISHED;
  return error;
}
