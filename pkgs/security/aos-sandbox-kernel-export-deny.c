// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/magic.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "aos-sandbox-kernel-export-deny.h"

#ifndef AOS_KERNEL_EXPORT_DENY_OBJECT
#error "AOS_KERNEL_EXPORT_DENY_OBJECT must name the fixed packaged BPF object"
#endif

#define PIN_ROOT "/sys/fs/bpf/aos"
#define PIN_DIR PIN_ROOT "/kernel-export-deny"
#define MAP_PIN PIN_DIR "/denied_mounts"

static const char *const program_names[] = {
    "aos_deny_open",   "aos_deny_access", "aos_deny_mmap",
    "aos_deny_mprot",  "aos_deny_lock",   "aos_deny_recv",
    "aos_deny_fcntl",  "aos_deny_ioctl",  "aos_deny_iocmp",
};

#define PROGRAM_COUNT (sizeof(program_names) / sizeof(program_names[0]))

static int pin_path(char *path, size_t size, const char *name)
{
  int length = snprintf(path, size, PIN_DIR "/%s", name);
  return length > 0 && (size_t)length < size ? 0 : -1;
}

static int check_bpffs(void)
{
  struct statfs fs;
  struct stat root;

  if (statfs("/sys/fs/bpf", &fs) != 0 || fs.f_type != BPF_FS_MAGIC) {
    fprintf(stderr, "kernel-export-deny: /sys/fs/bpf is not bpffs\n");
    return -1;
  }
  if (lstat(PIN_ROOT, &root) != 0 || !S_ISDIR(root.st_mode) ||
      root.st_uid != 0 || (root.st_mode & 0022) != 0) {
    fprintf(stderr, "kernel-export-deny: protected bpffs root is unavailable\n");
    return -1;
  }
  if (mkdir(PIN_DIR, 0700) != 0 && errno != EEXIST) {
    perror("kernel-export-deny: mkdir");
    return -1;
  }
  if (lstat(PIN_DIR, &root) != 0 || !S_ISDIR(root.st_mode) ||
      root.st_uid != 0 || (root.st_mode & 0077) != 0 ||
      statfs(PIN_DIR, &fs) != 0 || fs.f_type != BPF_FS_MAGIC) {
    fprintf(stderr, "kernel-export-deny: pin directory is not private to root\n");
    return -1;
  }
  return 0;
}

static int mount_id_from_fd(int source_fd, __u64 *mount_id)
{
  struct statx state = {0};

  if (source_fd < 0 ||
      syscall(SYS_statx, source_fd, "", AT_EMPTY_PATH,
              STATX_MNT_ID_UNIQUE, &state) != 0 ||
      (state.stx_mask & STATX_MNT_ID_UNIQUE) == 0 ||
      state.stx_mnt_id == 0) {
    fprintf(stderr, "kernel-export-deny: source FD has no unique mount ID\n");
    return -1;
  }
  *mount_id = state.stx_mnt_id;
  return 0;
}

static int inspect_link(const char *name)
{
  struct bpf_link_info link_info = {0};
  struct bpf_prog_info program_info = {0};
  __u32 info_size = sizeof(link_info);
  char path[PATH_MAX];
  int link_fd = -1;
  int program_fd = -1;
  int result = -1;

  if (pin_path(path, sizeof(path), name) != 0)
    return -1;
  link_fd = bpf_obj_get(path);
  if (link_fd < 0 ||
      bpf_obj_get_info_by_fd(link_fd, &link_info, &info_size) != 0 ||
      link_info.type != BPF_LINK_TYPE_TRACING || link_info.prog_id == 0 ||
      link_info.tracing.attach_type != BPF_LSM_MAC)
    goto out;

  program_fd = bpf_prog_get_fd_by_id(link_info.prog_id);
  info_size = sizeof(program_info);
  if (program_fd < 0 ||
      bpf_obj_get_info_by_fd(program_fd, &program_info, &info_size) != 0 ||
      program_info.type != BPF_PROG_TYPE_LSM ||
      strcmp((const char *)program_info.name, name) != 0)
    goto out;
  result = 0;

out:
  if (program_fd >= 0)
    close(program_fd);
  if (link_fd >= 0)
    close(link_fd);
  return result;
}

static int inspect_installation(__u64 mount_id)
{
  struct bpf_map_info map_info = {0};
  struct aos_kernel_export_deny_v1 state;
  __u32 info_size = sizeof(map_info);
  int map_fd = bpf_obj_get(MAP_PIN);
  int result = -1;

  if (map_fd < 0 ||
      bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size) != 0 ||
      map_info.type != BPF_MAP_TYPE_HASH ||
      map_info.key_size != sizeof(mount_id) ||
      map_info.value_size != sizeof(state) ||
      map_info.max_entries != AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS ||
      map_info.map_flags != BPF_F_RDONLY_PROG ||
      strcmp((const char *)map_info.name, "denied_mounts") != 0 ||
      bpf_map_lookup_elem(map_fd, &mount_id, &state) != 0 ||
      state.version != AOS_KERNEL_EXPORT_DENY_VERSION ||
      state.epoch != 1 || state.reserved != 0)
    goto out;

  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    if (inspect_link(program_names[i]) != 0)
      goto out;
  }
  result = 0;

out:
  if (map_fd >= 0)
    close(map_fd);
  return result;
}

static int validate_object(void)
{
  struct bpf_object *object = bpf_object__open_file(
      AOS_KERNEL_EXPORT_DENY_OBJECT, NULL);
  struct bpf_map *map;
  int result = -1;

  if (libbpf_get_error(object) != 0)
    return -1;
  map = bpf_object__find_map_by_name(object, "denied_mounts");
  if (map == NULL || bpf_map__type(map) != BPF_MAP_TYPE_HASH ||
      bpf_map__key_size(map) != sizeof(__u64) ||
      bpf_map__value_size(map) != sizeof(struct aos_kernel_export_deny_v1) ||
      bpf_map__max_entries(map) != AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS ||
      bpf_map__map_flags(map) != BPF_F_RDONLY_PROG)
    goto out;

  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    struct bpf_program *program =
        bpf_object__find_program_by_name(object, program_names[i]);
    if (program == NULL || bpf_program__type(program) != BPF_PROG_TYPE_LSM)
      goto out;
  }
  result = 0;

out:
  bpf_object__close(object);
  return result;
}

static int install(__u64 mount_id)
{
  struct bpf_object *object = NULL;
  struct bpf_link *links[PROGRAM_COUNT] = {0};
  bool pinned[PROGRAM_COUNT] = {0};
  bool map_pinned = false;
  struct bpf_map *map;
  struct aos_kernel_export_deny_v1 state = {
      .epoch = 1,
      .version = AOS_KERNEL_EXPORT_DENY_VERSION,
  };
  int result = -1;

  if (check_bpffs() != 0)
    return -1;
  if (access(MAP_PIN, F_OK) == 0 || errno != ENOENT) {
    fprintf(stderr, "kernel-export-deny: existing installation requires review\n");
    return -1;
  }
  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    char path[PATH_MAX];

    if (pin_path(path, sizeof(path), program_names[i]) != 0 ||
        access(path, F_OK) == 0 || errno != ENOENT) {
      fprintf(stderr, "kernel-export-deny: partial installation exists\n");
      return -1;
    }
  }

  object = bpf_object__open_file(AOS_KERNEL_EXPORT_DENY_OBJECT, NULL);
  if (libbpf_get_error(object) != 0 || bpf_object__load(object) != 0)
    goto out;
  map = bpf_object__find_map_by_name(object, "denied_mounts");
  if (map == NULL ||
      bpf_map_update_elem(bpf_map__fd(map), &mount_id, &state, BPF_NOEXIST) != 0)
    goto out;

  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    struct bpf_program *program =
        bpf_object__find_program_by_name(object, program_names[i]);
    if (program == NULL)
      goto out;
    links[i] = bpf_program__attach_lsm(program);
    if (libbpf_get_error(links[i]) != 0) {
      links[i] = NULL;
      goto out;
    }
  }

  if (bpf_map__pin(map, MAP_PIN) != 0)
    goto out;
  map_pinned = true;
  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    char path[PATH_MAX];

    if (pin_path(path, sizeof(path), program_names[i]) != 0 ||
        bpf_link__pin(links[i], path) != 0)
      goto out;
    pinned[i] = true;
  }

  if (inspect_installation(mount_id) != 0)
    goto out;
  result = 0;

out:
  if (result != 0) {
    /* No grant is issued on failure; the caller must retain source custody. */
    for (size_t i = 0; i < PROGRAM_COUNT; i++) {
      char path[PATH_MAX];
      if (pinned[i] && pin_path(path, sizeof(path), program_names[i]) == 0)
        unlink(path);
    }
    if (map_pinned)
      unlink(MAP_PIN);
    fprintf(stderr, "kernel-export-deny: installation failed\n");
  }
  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    if (links[i] != NULL)
      bpf_link__destroy(links[i]);
  }
  if (object != NULL && libbpf_get_error(object) == 0)
    bpf_object__close(object);
  return result;
}

int main(int argc, char **argv)
{
  char *end = NULL;
  long source_fd;
  __u64 mount_id;

  if (argc == 2 && strcmp(argv[1], "validate") == 0)
    return validate_object() == 0 ? 0 : 1;

  if (argc != 3 ||
      (strcmp(argv[1], "install") != 0 && strcmp(argv[1], "inspect") != 0)) {
    fprintf(stderr,
            "usage: aos-sandbox-kernel-export-deny validate\n"
            "       aos-sandbox-kernel-export-deny install|inspect FD\n");
    return 2;
  }
  errno = 0;
  source_fd = strtol(argv[2], &end, 10);
  if (errno != 0 || end == argv[2] || *end != '\0' ||
      source_fd < 0 || source_fd > INT_MAX ||
      mount_id_from_fd((int)source_fd, &mount_id) != 0)
    return 2;

  if (strcmp(argv[1], "install") == 0)
    return install(mount_id) == 0 ? 0 : 1;
  if (check_bpffs() != 0 || inspect_installation(mount_id) != 0) {
    fprintf(stderr, "kernel-export-deny: physical policy readback failed\n");
    return 1;
  }
  return 0;
}
