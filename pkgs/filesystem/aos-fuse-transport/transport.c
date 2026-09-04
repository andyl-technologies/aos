/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#define FUSE_USE_VERSION 317

#include "aos_fuse_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <fuse_lowlevel.h>
#include <linux/major.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define FUSE_DEVICE_MINOR 229
#define MAX_NAME_BYTES 255U
#define MAX_SYMLINK_BYTES 4096U
#define MAX_READDIR_BYTES (1024U * 1024U)
#define MAX_READDIR_ENTRIES 65536U
#define MAX_WRITE_BYTES (1024U * 1024U)
#define MAX_FUSE_PAGES 256U
#define MAX_TTL_NS UINT64_C(86400000000000)

struct aos_fuse_transport {
  const struct aos_fuse_core_operations *operations;
  void *core_context;
  struct aos_fuse_limits limits;
  struct fuse_session *session;
  int cancellation_fd;
  int terminal_error;
  uint8_t *target;
  uint8_t *names;
  char *name;
  char *directory_output;
  struct aos_fuse_directory_entry *entries;
  bool initialized;
  bool destroyed;
};

struct aos_fuse_open_responder {
  struct aos_fuse_transport *transport;
  fuse_req_t request;
  struct fuse_file_info *file;
  bool attempted;
};

static int normalize_error(int error) {
  switch (error) {
  case 0:
  case EACCES:
  case EAGAIN:
  case EBADF:
  case EBUSY:
  case EINVAL:
  case EINTR:
  case EIO:
  case ENAMETOOLONG:
  case ENOENT:
  case ENOMEM:
  case ENOSPC:
  case ENOTDIR:
  case ENOTSUP:
  case EOVERFLOW:
  case EROFS:
  case ESTALE:
  case ETIMEDOUT:
    return error;
  default:
    return EIO;
  }
}

static int core_result(int result, bool *fatal) {
  *fatal = result == AOS_FUSE_CORE_FATAL;
  return *fatal ? EIO : normalize_error(result);
}

static int power_of_ten(uint32_t value) {
  if (value == 0 || value > 1000000000U)
    return 0;
  while (value > 1 && value % 10 == 0)
    value /= 10;
  return value == 1;
}

static int validate_contract(const struct aos_fuse_core_operations *ops,
                             const struct aos_fuse_limits *limits) {
  if (ops == NULL || limits == NULL ||
      ops->abi_major != AOS_FUSE_TRANSPORT_ABI_MAJOR ||
      ops->abi_minor > AOS_FUSE_TRANSPORT_ABI_MINOR ||
      ops->struct_size != sizeof(*ops) ||
      ops->attributes_size != sizeof(struct aos_fuse_attributes) ||
      ops->directory_entry_size != sizeof(struct aos_fuse_directory_entry) ||
      ops->limits_size != sizeof(struct aos_fuse_limits) || ops->flags != 0 ||
      ops->reserved != 0 || ops->lookup == NULL ||
      ops->forget == NULL || ops->getattr == NULL || ops->readlink == NULL ||
      ops->opendir == NULL || ops->readdir == NULL || ops->releasedir == NULL ||
      ops->destroy == NULL)
    return EINVAL;
  if (limits->struct_size != sizeof(*limits) ||
      limits->abi_major != AOS_FUSE_TRANSPORT_ABI_MAJOR ||
      limits->abi_minor > AOS_FUSE_TRANSPORT_ABI_MINOR || limits->flags != 0 ||
      limits->reserved0 != 0 || limits->reserved1 != 0 ||
      limits->maximum_name_bytes == 0 ||
      limits->maximum_name_bytes > MAX_NAME_BYTES ||
      limits->maximum_symlink_bytes == 0 ||
      limits->maximum_symlink_bytes > MAX_SYMLINK_BYTES ||
      limits->maximum_readdir_bytes == 0 ||
      limits->maximum_readdir_bytes > MAX_READDIR_BYTES ||
      limits->maximum_readdir_entries == 0 ||
      limits->maximum_readdir_entries > MAX_READDIR_ENTRIES ||
      limits->maximum_write_bytes < 4096 ||
      limits->maximum_write_bytes > MAX_WRITE_BYTES ||
      limits->maximum_pages == 0 || limits->maximum_pages > MAX_FUSE_PAGES ||
      limits->request_timeout_seconds == 0 ||
      limits->request_timeout_seconds > 300 ||
      limits->entry_valid_ns > MAX_TTL_NS ||
      limits->attribute_valid_ns > MAX_TTL_NS ||
      !power_of_ten(limits->time_granularity_ns))
    return EINVAL;
  return 0;
}

static mode_t kind_mode(uint8_t kind) {
  switch (kind) {
  case AOS_FUSE_KIND_FILE:
    return S_IFREG;
  case AOS_FUSE_KIND_DIRECTORY:
    return S_IFDIR;
  case AOS_FUSE_KIND_SYMLINK:
    return S_IFLNK;
  default:
    return 0;
  }
}

static mode_t node_mode(const struct aos_fuse_attributes *attributes) {
  mode_t type = kind_mode(attributes->kind);
  if (type == 0 || attributes->reserved != 0 || attributes->node_id == 0 ||
      attributes->mode > 07777 || attributes->mtime_nanos >= 1000000000U ||
      attributes->nlink == 0)
    return 0;
  return type | attributes->mode;
}

static int fill_stat(const struct aos_fuse_attributes *attributes,
                     struct stat *output) {
  mode_t mode = node_mode(attributes);
  if (mode == 0)
    return EIO;
  memset(output, 0, sizeof(*output));
  output->st_ino = attributes->node_id;
  if ((uint64_t)output->st_ino != attributes->node_id)
    return EOVERFLOW;
  output->st_mode = mode;
  output->st_nlink = attributes->nlink;
  if ((uint64_t)output->st_nlink != attributes->nlink)
    return EOVERFLOW;
  output->st_uid = attributes->uid;
  if ((uint64_t)output->st_uid != attributes->uid)
    return EOVERFLOW;
  output->st_gid = attributes->gid;
  if ((uint64_t)output->st_gid != attributes->gid)
    return EOVERFLOW;
  output->st_size = (off_t)attributes->size;
  if (output->st_size < 0 || (uint64_t)output->st_size != attributes->size)
    return EOVERFLOW;
  uint64_t blocks = attributes->size / 512U;
  if (attributes->size % 512U != 0)
    blocks++;
  output->st_blocks = (blkcnt_t)blocks;
  if (output->st_blocks < 0 || (uint64_t)output->st_blocks != blocks)
    return EOVERFLOW;
  output->st_blksize = 4096;
  output->st_mtim.tv_sec = (time_t)attributes->mtime_seconds;
  if ((int64_t)output->st_mtim.tv_sec != attributes->mtime_seconds)
    return EOVERFLOW;
  output->st_mtim.tv_nsec = attributes->mtime_nanos;
  output->st_atim = output->st_mtim;
  output->st_ctim = output->st_mtim;
  return 0;
}

static double seconds(uint64_t nanoseconds) {
  return (double)(nanoseconds / 1000000000U) +
         (double)(nanoseconds % 1000000000U) / 1000000000.0;
}

static struct aos_fuse_transport *transport_for(fuse_req_t request) {
  return fuse_req_userdata(request);
}

static int interrupted(fuse_req_t request) {
  return fuse_req_interrupted(request) ? EINTR : 0;
}

static void poison(struct aos_fuse_transport *transport, int error) {
  if (transport->terminal_error == 0)
    transport->terminal_error = error > 0 ? error : EIO;
  if (transport->session != NULL)
    fuse_session_exit(transport->session);
}

static int reply_failure(int result) {
  return result < 0 && result != INT_MIN ? -result : EIO;
}

static int checked_reply(struct aos_fuse_transport *transport, int result) {
  if (result == 0)
    return 0;
  int error = reply_failure(result);
  poison(transport, error);
  return error;
}

static void reply_error(fuse_req_t request, int error) {
  struct aos_fuse_transport *transport = transport_for(request);
  (void)checked_reply(transport,
                      fuse_reply_err(request, normalize_error(error)));
}

static void reply_integrity_failure(fuse_req_t request) {
  struct aos_fuse_transport *transport = transport_for(request);
  reply_error(request, EIO);
  poison(transport, EIO);
}

static void initialize(void *userdata, struct fuse_conn_info *connection) {
  struct aos_fuse_transport *transport = userdata;
  if (connection->proto_major != 7 || connection->proto_minor < 45) {
    fuse_session_exit(transport->session);
    return;
  }

  connection->want = 0;
  connection->want_ext = 0;
  connection->max_write = transport->limits.maximum_write_bytes;
  connection->max_read = transport->limits.maximum_write_bytes;
  connection->max_readahead = 0;
  connection->max_background = 1;
  connection->congestion_threshold = 1;
  connection->time_gran = transport->limits.time_granularity_ns;
  connection->request_timeout = transport->limits.request_timeout_seconds;
  connection->no_interrupt = 0;
  transport->initialized = true;
}

static void destroy(void *userdata) {
  struct aos_fuse_transport *transport = userdata;
  if (!transport->destroyed) {
    transport->operations->destroy(transport->core_context);
    transport->destroyed = true;
  }
}

static int reply_open_once(struct aos_fuse_open_responder *responder,
                           uint64_t handle) {
  if (responder == NULL || responder->attempted || handle == 0)
    return EINVAL;
  responder->attempted = true;
  responder->file->fh = handle;
  responder->file->cache_readdir = 1;
  int result = fuse_reply_open(responder->request, responder->file);
  return checked_reply(responder->transport, result);
}

static void lookup(fuse_req_t request, fuse_ino_t parent, const char *name) {
  struct aos_fuse_transport *transport = transport_for(request);
  size_t length = strnlen(name, transport->limits.maximum_name_bytes + 1U);
  if (length == 0 || length > transport->limits.maximum_name_bytes ||
      memchr(name, '/', length) != NULL) {
    reply_error(request,
                length > transport->limits.maximum_name_bytes ? ENAMETOOLONG
                                                               : EINVAL);
    return;
  }
  int error = interrupted(request);
  bool fatal = false;
  struct aos_fuse_attributes attributes;
  memset(&attributes, 0, sizeof(attributes));
  if (error == 0)
    error = core_result(transport->operations->lookup(
                            transport->core_context, parent,
                            (const uint8_t *)name, length, &attributes),
                        &fatal);
  if (fatal) {
    reply_error(request, EIO);
    poison(transport, EIO);
    return;
  }
  if (error == ENOENT) {
    struct fuse_entry_param entry;
    memset(&entry, 0, sizeof(entry));
    entry.entry_timeout = seconds(transport->limits.entry_valid_ns);
    (void)checked_reply(transport, fuse_reply_entry(request, &entry));
    return;
  }
  if (error != 0) {
    reply_error(request, error);
    return;
  }
  struct fuse_entry_param entry;
  memset(&entry, 0, sizeof(entry));
  entry.ino = attributes.node_id;
  entry.generation = 1;
  error = fill_stat(&attributes, &entry.attr);
  if (error != 0) {
    reply_integrity_failure(request);
    return;
  }
  entry.attr_timeout = seconds(transport->limits.attribute_valid_ns);
  entry.entry_timeout = seconds(transport->limits.entry_valid_ns);
  (void)checked_reply(transport, fuse_reply_entry(request, &entry));
}

static void forget(fuse_req_t request, fuse_ino_t node, uint64_t count) {
  struct aos_fuse_transport *transport = transport_for(request);
  if (transport->terminal_error != 0) {
    fuse_reply_none(request);
    return;
  }
  int raw_error =
      transport->operations->forget(transport->core_context, node, count);
  bool fatal = false;
  int error = core_result(raw_error, &fatal);
  fuse_reply_none(request);
  if (error != 0)
    poison(transport, fatal ? EIO : error);
}

static void getattr(fuse_req_t request, fuse_ino_t node,
                    struct fuse_file_info *file) {
  (void)file;
  struct aos_fuse_transport *transport = transport_for(request);
  struct aos_fuse_attributes attributes;
  memset(&attributes, 0, sizeof(attributes));
  int error = interrupted(request);
  bool fatal = false;
  bool invalid_output = false;
  if (error == 0)
    error = core_result(transport->operations->getattr(
                            transport->core_context, node, &attributes),
                        &fatal);
  struct stat output;
  if (error == 0) {
    error = fill_stat(&attributes, &output);
    invalid_output = error != 0;
  }
  if (error != 0) {
    if (invalid_output)
      reply_integrity_failure(request);
    else
      reply_error(request, error);
    if (fatal)
      poison(transport, EIO);
    return;
  }
  (void)checked_reply(
      transport, fuse_reply_attr(request, &output,
                                 seconds(transport->limits.attribute_valid_ns)));
}

static void aos_readlink(fuse_req_t request, fuse_ino_t node) {
  struct aos_fuse_transport *transport = transport_for(request);
  uint64_t callback_length = 0;
  memset(transport->target, 0,
         (size_t)transport->limits.maximum_symlink_bytes + 1U);
  int error = interrupted(request);
  bool fatal = false;
  bool invalid_output = false;
  if (error == 0)
    error = core_result(transport->operations->readlink(
                            transport->core_context, node, transport->target,
                            transport->limits.maximum_symlink_bytes,
                            &callback_length),
                        &fatal);
  size_t length = (size_t)callback_length;
  if (error == 0 &&
      (callback_length != (uint64_t)length || length == 0 ||
       length > transport->limits.maximum_symlink_bytes ||
       memchr(transport->target, '\0', length) != NULL))
    invalid_output = true;
  if (invalid_output)
    error = EIO;
  if (error != 0) {
    if (invalid_output)
      reply_integrity_failure(request);
    else
      reply_error(request, error);
    if (fatal)
      poison(transport, EIO);
    return;
  }
  transport->target[length] = '\0';
  (void)checked_reply(
      transport, fuse_reply_readlink(request, (const char *)transport->target));
}

static void opendir(fuse_req_t request, fuse_ino_t node,
                    struct fuse_file_info *file) {
  struct aos_fuse_transport *transport = transport_for(request);
  struct fuse_file_info reply_file;
  memset(&reply_file, 0, sizeof(reply_file));
  reply_file.flags = file->flags;
  int error = interrupted(request);
  bool fatal = false;
  struct aos_fuse_open_responder responder = {
      .transport = transport,
      .request = request,
      .file = &reply_file,
      .attempted = false};
  if (error == 0)
    error = core_result(transport->operations->opendir(
                            transport->core_context, node, &responder,
                            reply_open_once),
                        &fatal);
  if (!responder.attempted) {
    if (error == 0)
      reply_integrity_failure(request);
    else
      reply_error(request, error);
    if (fatal)
      poison(transport, EIO);
  } else if (error != 0 || fatal) {
    poison(transport, fatal ? EIO : error);
  }
}

static void readdir(fuse_req_t request, fuse_ino_t node, size_t size,
                    off_t offset, struct fuse_file_info *file) {
  struct aos_fuse_transport *transport = transport_for(request);
  if (offset < 0) {
    reply_error(request, EINVAL);
    return;
  }
  size_t limit = size;
  if (limit > transport->limits.maximum_readdir_bytes)
    limit = transport->limits.maximum_readdir_bytes;
  uint64_t callback_entry_count = 0;
  uint64_t callback_names_length = 0;
  memset(transport->entries, 0,
         (size_t)transport->limits.maximum_readdir_entries *
             sizeof(*transport->entries));
  memset(transport->names, 0, transport->limits.maximum_readdir_bytes);
  memset(transport->name, 0,
         (size_t)transport->limits.maximum_name_bytes + 1U);
  memset(transport->directory_output, 0,
         transport->limits.maximum_readdir_bytes);
  int error = interrupted(request);
  bool fatal = false;
  if (error == 0)
    error = core_result(transport->operations->readdir(
                            transport->core_context, node, file->fh,
                            (uint64_t)offset, limit, transport->entries,
                            transport->limits.maximum_readdir_entries,
                            &callback_entry_count, transport->names,
                            transport->limits.maximum_readdir_bytes,
                            &callback_names_length),
                        &fatal);
  if (error != 0) {
    reply_error(request, error);
    if (fatal)
      poison(transport, EIO);
    return;
  }
  if (callback_entry_count > transport->limits.maximum_readdir_entries ||
      callback_names_length > transport->limits.maximum_readdir_bytes) {
    reply_integrity_failure(request);
    return;
  }
  size_t entry_count = (size_t)callback_entry_count;
  size_t names_length = (size_t)callback_names_length;

  size_t used = 0;
  uint64_t previous_cookie = (uint64_t)offset;
  bool output_full = false;
  for (size_t index = 0; index < entry_count; ++index) {
    const struct aos_fuse_directory_entry *entry = &transport->entries[index];
    size_t begin = entry->name_offset;
    size_t length = entry->name_length;
    if (entry->reserved != 0 || length == 0 ||
        length > transport->limits.maximum_name_bytes || begin > names_length ||
        length > names_length - begin ||
        entry->next_cookie > (uint64_t)INT64_MAX ||
        entry->next_cookie <= previous_cookie ||
        memchr(transport->names + begin, '\0', length) != NULL ||
        memchr(transport->names + begin, '/', length) != NULL) {
      reply_integrity_failure(request);
      return;
    }
    previous_cookie = entry->next_cookie;
    memcpy(transport->name, transport->names + begin, length);
    transport->name[length] = '\0';
    struct stat stat;
    memset(&stat, 0, sizeof(stat));
    stat.st_ino = entry->node_id;
    stat.st_mode = kind_mode(entry->kind);
    if ((uint64_t)stat.st_ino != entry->node_id || stat.st_mode == 0) {
      reply_integrity_failure(request);
      return;
    }
    if (!output_full) {
      size_t needed = fuse_add_direntry(request, NULL, 0, transport->name,
                                        &stat, (off_t)entry->next_cookie);
      if (needed > limit - used) {
        output_full = true;
      } else {
        size_t packed = fuse_add_direntry(
            request, transport->directory_output + used, limit - used,
            transport->name, &stat, (off_t)entry->next_cookie);
        if (packed != needed) {
          reply_integrity_failure(request);
          return;
        }
        used += needed;
      }
    }
  }
  (void)checked_reply(
      transport, fuse_reply_buf(request, transport->directory_output, used));
}

static void releasedir(fuse_req_t request, fuse_ino_t node,
                       struct fuse_file_info *file) {
  struct aos_fuse_transport *transport = transport_for(request);
  bool fatal = false;
  int error = core_result(transport->operations->releasedir(
                              transport->core_context, node, file->fh),
                          &fatal);
  (void)checked_reply(transport, fuse_reply_err(request, error));
  if (fatal)
    poison(transport, EIO);
}

static void aos_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                        int to_set, struct fuse_file_info *fi) {
  (void)ino; (void)attr; (void)to_set; (void)fi;
  reply_error(req, EROFS);
}
static void aos_mknod(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode, dev_t device) {
  (void)parent; (void)name; (void)mode; (void)device;
  reply_error(req, EROFS);
}
static void aos_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode) {
  (void)parent; (void)name; (void)mode;
  reply_error(req, EROFS);
}
static void aos_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
  (void)parent; (void)name;
  reply_error(req, EROFS);
}
static void aos_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
  (void)parent; (void)name;
  reply_error(req, EROFS);
}
static void aos_symlink(fuse_req_t req, const char *link, fuse_ino_t parent,
                        const char *name) {
  (void)link; (void)parent; (void)name;
  reply_error(req, EROFS);
}
static void aos_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
                       fuse_ino_t new_parent, const char *new_name,
                       unsigned int flags) {
  (void)parent; (void)name; (void)new_parent; (void)new_name; (void)flags;
  reply_error(req, EROFS);
}
static void aos_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t new_parent,
                     const char *new_name) {
  (void)ino; (void)new_parent; (void)new_name;
  reply_error(req, EROFS);
}
static void aos_open(fuse_req_t req, fuse_ino_t ino,
                     struct fuse_file_info *fi) {
  (void)ino; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *fi) {
  (void)ino; (void)size; (void)off; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_write(fuse_req_t req, fuse_ino_t ino, const char *buffer,
                      size_t size, off_t off, struct fuse_file_info *fi) {
  (void)ino; (void)buffer; (void)size; (void)off; (void)fi;
  reply_error(req, EROFS);
}
static void aos_flush(fuse_req_t req, fuse_ino_t ino,
                      struct fuse_file_info *fi) {
  (void)ino; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_release(fuse_req_t req, fuse_ino_t ino,
                        struct fuse_file_info *fi) {
  (void)ino; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
                      struct fuse_file_info *fi) {
  (void)ino; (void)datasync; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_fsyncdir(fuse_req_t req, fuse_ino_t ino, int datasync,
                         struct fuse_file_info *fi) {
  (void)ino; (void)datasync; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_statfs(fuse_req_t req, fuse_ino_t ino) {
  (void)ino;
  reply_error(req, ENOTSUP);
}
static void aos_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                         const char *value, size_t size, int flags) {
  (void)ino; (void)name; (void)value; (void)size; (void)flags;
  reply_error(req, EROFS);
}
static void aos_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                         size_t size) {
  (void)ino; (void)name; (void)size;
  reply_error(req, ENOTSUP);
}
static void aos_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {
  (void)ino; (void)size;
  reply_error(req, ENOTSUP);
}
static void aos_removexattr(fuse_req_t req, fuse_ino_t ino,
                            const char *name) {
  (void)ino; (void)name;
  reply_error(req, EROFS);
}
static void aos_access(fuse_req_t req, fuse_ino_t ino, int mask) {
  (void)ino; (void)mask;
  reply_error(req, ENOTSUP);
}
static void aos_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                       mode_t mode, struct fuse_file_info *fi) {
  (void)parent; (void)name; (void)mode; (void)fi;
  reply_error(req, EROFS);
}
static void aos_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
                          off_t offset, off_t length,
                          struct fuse_file_info *fi) {
  (void)ino; (void)mode; (void)offset; (void)length; (void)fi;
  reply_error(req, EROFS);
}
static void aos_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
                            off_t off, struct fuse_file_info *fi) {
  (void)ino; (void)size; (void)off; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
                      struct fuse_file_info *fi) {
  (void)ino; (void)off; (void)whence; (void)fi;
  reply_error(req, ENOTSUP);
}
static void aos_tmpfile(fuse_req_t req, fuse_ino_t parent, mode_t mode,
                        struct fuse_file_info *fi) {
  (void)parent; (void)mode; (void)fi;
  reply_error(req, EROFS);
}
static void aos_copy_file_range(fuse_req_t req, fuse_ino_t ino_in,
                                off_t off_in, struct fuse_file_info *file_in,
                                fuse_ino_t ino_out, off_t off_out,
                                struct fuse_file_info *file_out, size_t length,
                                int flags) {
  (void)ino_in; (void)off_in; (void)file_in; (void)ino_out; (void)off_out;
  (void)file_out; (void)length; (void)flags;
  reply_error(req, EROFS);
}

static int begin_deadline(struct aos_fuse_transport *transport,
                          struct timespec *deadline) {
  if (clock_gettime(CLOCK_BOOTTIME, deadline) != 0) {
    int error = errno;
    poison(transport, error);
    return error;
  }
  deadline->tv_sec += transport->limits.request_timeout_seconds;
  return 0;
}

static int remaining_milliseconds(struct aos_fuse_transport *transport,
                                  const struct timespec *deadline) {
  struct timespec now;
  if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) {
    int error = errno;
    poison(transport, error);
    return -error;
  }
  int64_t seconds_left = (int64_t)deadline->tv_sec - (int64_t)now.tv_sec;
  int64_t nanos_left = (int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec;
  if (nanos_left < 0) {
    seconds_left--;
    nanos_left += 1000000000;
  }
  if (seconds_left < 0 || (seconds_left == 0 && nanos_left == 0)) {
    poison(transport, ETIMEDOUT);
    return -ETIMEDOUT;
  }
  int64_t milliseconds =
      seconds_left * 1000 + (nanos_left + 999999) / 1000000;
  return milliseconds > INT_MAX ? INT_MAX : (int)milliseconds;
}

static int wait_for_io(struct aos_fuse_transport *transport, int fd,
                       short events, const struct timespec *deadline) {
  for (;;) {
    int timeout = remaining_milliseconds(transport, deadline);
    if (timeout < 0)
      errno = -timeout;
    if (timeout < 0)
      return -timeout;
    struct pollfd descriptors[2] = {
        {.fd = fd, .events = events},
        {.fd = transport->cancellation_fd, .events = POLLIN},
    };
    int ready = poll(descriptors, 2, timeout);
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready < 0) {
      int error = errno;
      poison(transport, error);
      errno = error;
      return error;
    }
    if (ready == 0) {
      poison(transport, ETIMEDOUT);
      errno = ETIMEDOUT;
      return ETIMEDOUT;
    }
    if ((descriptors[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) !=
        0) {
      poison(transport, ECANCELED);
      errno = ECANCELED;
      return ECANCELED;
    }
    if ((descriptors[0].revents & events) != 0)
      return 0;
    poison(transport, EIO);
    errno = EIO;
    return EIO;
  }
}

static ssize_t custom_read(int fd, void *buffer, size_t length, void *userdata) {
  struct aos_fuse_transport *transport = userdata;
  for (;;) {
    struct pollfd descriptors[2] = {
        {.fd = fd, .events = POLLIN},
        {.fd = transport->cancellation_fd, .events = POLLIN},
    };
    int ready = poll(descriptors, 2, -1);
    if (ready < 0 && errno == EINTR)
      continue;
    if (ready < 0) {
      int error = errno;
      poison(transport, error);
      return -1;
    }
    if ((descriptors[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) !=
        0) {
      poison(transport, ECANCELED);
      errno = ECANCELED;
      return -1;
    }
    if ((descriptors[0].revents & POLLIN) == 0) {
      poison(transport, EIO);
      errno = EIO;
      return -1;
    }
    ssize_t result = read(fd, buffer, length);
    if (result > 0)
      return result;
    if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    int error = result == 0 ? ENODEV : errno;
    poison(transport, error);
    errno = error;
    return -1;
  }
}

static ssize_t custom_writev(int fd, struct iovec *iov, int count,
                             void *userdata) {
  struct aos_fuse_transport *transport = userdata;
  if (count <= 0 || count > IOV_MAX) {
    poison(transport, EINVAL);
    errno = EINVAL;
    return -1;
  }
  size_t total = 0;
  for (int index = 0; index < count; ++index) {
    if (iov[index].iov_len > (size_t)SSIZE_MAX - total) {
      poison(transport, EOVERFLOW);
      errno = EOVERFLOW;
      return -1;
    }
    total += iov[index].iov_len;
  }
  struct timespec deadline;
  if (begin_deadline(transport, &deadline) != 0)
    return -1;

  for (;;) {
    if (wait_for_io(transport, fd, POLLOUT, &deadline) != 0)
      return -1;
    ssize_t result = writev(fd, iov, count);
    if (result < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
      continue;
    if (result < 0) {
      int error = errno;
      poison(transport, error);
      return -1;
    }
    if ((size_t)result != total) {
      int error = EIO;
      poison(transport, error);
      errno = error;
      return -1;
    }
    return result;
  }
}

static int run_transport(int fd, int cancellation_fd,
                         const struct aos_fuse_core_operations *operations,
                         void *core_context,
                         const struct aos_fuse_limits *limits,
                         bool validate_device) {
  int error = validate_contract(operations, limits);
  if (error != 0 || fd < 0 || cancellation_fd < 0)
    return error == 0 ? EBADF : error;
  if (fd == cancellation_fd)
    return EINVAL;
  int fd_flags = fcntl(fd, F_GETFL);
  int cancellation_flags = fcntl(cancellation_fd, F_GETFL);
  if (fd_flags < 0 || cancellation_flags < 0)
    return errno;
  if ((fd_flags & O_ACCMODE) != O_RDWR || (fd_flags & O_NONBLOCK) == 0 ||
      (cancellation_flags & O_ACCMODE) == O_WRONLY ||
      (cancellation_flags & O_NONBLOCK) == 0)
    return EBADF;
  struct stat fd_status;
  struct stat cancellation_status;
  if (fstat(fd, &fd_status) != 0 ||
      fstat(cancellation_fd, &cancellation_status) != 0)
    return errno;
  if (fd_status.st_dev == cancellation_status.st_dev &&
      fd_status.st_ino == cancellation_status.st_ino)
    return EINVAL;
  long page_size = sysconf(_SC_PAGESIZE);
  uint64_t derived_pages =
      page_size > 0
          ? ((uint64_t)limits->maximum_write_bytes + (uint64_t)page_size - 1U) /
                (uint64_t)page_size
          : 0;
  if (page_size <= 0 || derived_pages != limits->maximum_pages)
    return EINVAL;
  if (validate_device) {
    if (!S_ISCHR(fd_status.st_mode) || major(fd_status.st_rdev) != MISC_MAJOR ||
        minor(fd_status.st_rdev) != FUSE_DEVICE_MINOR)
      return ENODEV;
  }
  int session_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
  if (session_fd < 0)
    return errno;

  struct aos_fuse_transport transport;
  memset(&transport, 0, sizeof(transport));
  transport.operations = operations;
  transport.core_context = core_context;
  transport.limits = *limits;
  transport.cancellation_fd = cancellation_fd;
  transport.target = calloc((size_t)limits->maximum_symlink_bytes + 1U, 1);
  transport.names = calloc(limits->maximum_readdir_bytes, 1);
  transport.name = calloc((size_t)limits->maximum_name_bytes + 1U, 1);
  transport.directory_output = calloc(limits->maximum_readdir_bytes, 1);
  transport.entries = calloc(limits->maximum_readdir_entries,
                             sizeof(*transport.entries));
  if (transport.target == NULL || transport.names == NULL ||
      transport.name == NULL || transport.directory_output == NULL ||
      transport.entries == NULL) {
    error = ENOMEM;
    goto cleanup;
  }

  char mount_options[96];
  int option_length = snprintf(mount_options, sizeof(mount_options),
                               "-odefault_permissions,ro,max_read=%u",
                               limits->maximum_write_bytes);
  if (option_length < 0 || (size_t)option_length >= sizeof(mount_options)) {
    error = EOVERFLOW;
    goto cleanup;
  }
  char *arguments[] = {(char *)"aos-fuse-transport", mount_options};
  struct fuse_args args = FUSE_ARGS_INIT(2, arguments);
  struct fuse_lowlevel_ops lowlevel;
  memset(&lowlevel, 0, sizeof(lowlevel));
  lowlevel.init = initialize;
  lowlevel.destroy = destroy;
  lowlevel.lookup = lookup;
  lowlevel.forget = forget;
  lowlevel.getattr = getattr;
  lowlevel.setattr = aos_setattr;
  lowlevel.readlink = aos_readlink;
  lowlevel.mknod = aos_mknod;
  lowlevel.mkdir = aos_mkdir;
  lowlevel.unlink = aos_unlink;
  lowlevel.rmdir = aos_rmdir;
  lowlevel.symlink = aos_symlink;
  lowlevel.rename = aos_rename;
  lowlevel.link = aos_link;
  lowlevel.open = aos_open;
  lowlevel.read = aos_read;
  lowlevel.write = aos_write;
  lowlevel.flush = aos_flush;
  lowlevel.release = aos_release;
  lowlevel.fsync = aos_fsync;
  lowlevel.opendir = opendir;
  lowlevel.readdir = readdir;
  lowlevel.releasedir = releasedir;
  lowlevel.fsyncdir = aos_fsyncdir;
  lowlevel.statfs = aos_statfs;
  lowlevel.setxattr = aos_setxattr;
  lowlevel.getxattr = aos_getxattr;
  lowlevel.listxattr = aos_listxattr;
  lowlevel.removexattr = aos_removexattr;
  lowlevel.access = aos_access;
  lowlevel.create = aos_create;
  lowlevel.fallocate = aos_fallocate;
  lowlevel.readdirplus = aos_readdirplus;
  lowlevel.copy_file_range = aos_copy_file_range;
  lowlevel.lseek = aos_lseek;
  lowlevel.tmpfile = aos_tmpfile;

  transport.session =
      fuse_session_new(&args, &lowlevel, sizeof(lowlevel), &transport);
  fuse_opt_free_args(&args);
  if (transport.session == NULL) {
    error = EINVAL;
    goto cleanup;
  }
  struct fuse_custom_io io = {.writev = custom_writev, .read = custom_read};
  int attached =
      fuse_session_custom_io(transport.session, &io, sizeof(io), session_fd);
  if (attached != 0) {
    error = -attached;
    fuse_session_destroy(transport.session);
    transport.session = NULL;
    goto cleanup;
  }
  session_fd = -1;
  error = fuse_session_loop(transport.session) == 0 ? 0 : EIO;
  if (transport.terminal_error != 0)
    error = transport.terminal_error;
  fuse_session_destroy(transport.session);
  transport.session = NULL;
  if (!transport.initialized && error == 0)
    error = EPROTO;

cleanup:
  if (session_fd >= 0)
    close(session_fd);
  free(transport.entries);
  free(transport.directory_output);
  free(transport.name);
  free(transport.names);
  free(transport.target);
  return error;
}

int aos_fuse_transport_run(int connected_fd, int cancellation_fd,
                           const struct aos_fuse_core_operations *operations,
                           void *core_context,
                           const struct aos_fuse_limits *limits) {
  return run_transport(connected_fd, cancellation_fd, operations, core_context,
                       limits, true);
}

#ifdef AOS_FUSE_TRANSPORT_TESTING
int aos_fuse_transport_run_test_fd(
    int connected_fd, int cancellation_fd,
    const struct aos_fuse_core_operations *operations,
    void *core_context, const struct aos_fuse_limits *limits) {
  return run_transport(connected_fd, cancellation_fd, operations, core_context,
                       limits, false);
}

int aos_fuse_transport_test_writev(int connected_fd, int cancellation_fd,
                                   const uint8_t *first, uint64_t first_length,
                                   const uint8_t *second,
                                   uint64_t second_length,
                                   uint16_t timeout_seconds,
                                   int *terminal_error) {
  if (first_length > SIZE_MAX || second_length > SIZE_MAX ||
      terminal_error == NULL)
    return EINVAL;
  struct aos_fuse_transport transport;
  memset(&transport, 0, sizeof(transport));
  transport.cancellation_fd = cancellation_fd;
  transport.limits.request_timeout_seconds = timeout_seconds;
  struct iovec vectors[2] = {
      {.iov_base = (void *)first, .iov_len = (size_t)first_length},
      {.iov_base = (void *)second, .iov_len = (size_t)second_length},
  };
  ssize_t result = custom_writev(connected_fd, vectors, 2, &transport);
  *terminal_error = transport.terminal_error;
  return result < 0 ? -1 : 0;
}
#endif
