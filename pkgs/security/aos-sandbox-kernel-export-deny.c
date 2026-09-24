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
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "aos-sandbox-kernel-export-deny.h"

#ifndef AOS_KERNEL_EXPORT_DENY_OBJECT
#error "AOS_KERNEL_EXPORT_DENY_OBJECT must name the fixed packaged BPF object"
#endif

#define PIN_ROOT "/sys/fs/bpf/aos"
#define PIN_DIR PIN_ROOT "/kernel-export-deny"
#define MOUNT_MAP_PIN PIN_DIR "/export_mounts"
#define GRANT_MAP_PIN PIN_DIR "/consumer_grants"
#define MAX_GRANT_TTL_MS 3600000ULL

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

static int cgroup_id_from_fd(int cgroup_fd, __u64 *cgroup_id)
{
  struct statfs fs;
  struct stat state;

  if (cgroup_fd < 0 || fstatfs(cgroup_fd, &fs) != 0 ||
      fs.f_type != CGROUP2_SUPER_MAGIC || fstat(cgroup_fd, &state) != 0 ||
      !S_ISDIR(state.st_mode) || state.st_ino == 0) {
    fprintf(stderr, "kernel-export-deny: consumer FD is not a cgroup-v2 directory\n");
    return -1;
  }
  /* On the supported 64-bit kernel, kernfs inode number is the BPF cgroup ID. */
  *cgroup_id = state.st_ino;
  return 0;
}

static int parse_fd(const char *text, int *fd)
{
  char *end = NULL;
  long value;

  errno = 0;
  value = strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' ||
      value < 0 || value > INT_MAX)
    return -1;
  *fd = (int)value;
  return 0;
}

static int hex_digit(char digit)
{
  if (digit >= '0' && digit <= '9')
    return digit - '0';
  if (digit >= 'a' && digit <= 'f')
    return digit - 'a' + 10;
  if (digit >= 'A' && digit <= 'F')
    return digit - 'A' + 10;
  return -1;
}

static int current_boot_id(__u64 boot_id[2])
{
  unsigned char bytes[16] = {0};
  char text[40] = {0};
  size_t byte_index = 0;
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  ssize_t length;

  if (fd < 0)
    return -1;
  length = read(fd, text, sizeof(text));
  close(fd);
  if (length < 36)
    return -1;

  for (size_t i = 0; i < 36;) {
    int high;
    int low;

    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (text[i] != '-')
        return -1;
      i++;
      continue;
    }
    if (i + 1 >= 36)
      return -1;
    high = hex_digit(text[i]);
    low = hex_digit(text[i + 1]);
    if (high < 0 || low < 0 || byte_index >= sizeof(bytes))
      return -1;
    bytes[byte_index++] = (unsigned char)((high << 4) | low);
    i += 2;
  }
  if (byte_index != sizeof(bytes))
    return -1;
  memcpy(boot_id, bytes, sizeof(bytes));
  return boot_id[0] == 0 && boot_id[1] == 0 ? -1 : 0;
}

static int boot_time_ns(__u64 *now)
{
  struct timespec clock;

  if (clock_gettime(CLOCK_BOOTTIME, &clock) != 0 || clock.tv_sec < 0 ||
      clock.tv_nsec < 0 || clock.tv_nsec >= 1000000000L)
    return -1;
  *now = (__u64)clock.tv_sec * 1000000000ULL + (__u64)clock.tv_nsec;
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

static int open_checked_map(const char *pin, const char *name,
                            __u32 key_size, __u32 value_size,
                            __u32 max_entries)
{
  struct bpf_map_info map_info = {0};
  __u32 info_size = sizeof(map_info);
  int map_fd = bpf_obj_get(pin);

  if (map_fd < 0 ||
      bpf_obj_get_info_by_fd(map_fd, &map_info, &info_size) != 0 ||
      map_info.type != BPF_MAP_TYPE_HASH ||
      map_info.key_size != key_size || map_info.value_size != value_size ||
      map_info.max_entries != max_entries || map_info.id == 0 ||
      map_info.map_flags != BPF_F_RDONLY_PROG ||
      strcmp((const char *)map_info.name, name) != 0) {
    if (map_fd >= 0)
      close(map_fd);
    return -1;
  }
  return map_fd;
}

static int inspect_installation(__u64 mount_id,
                                struct aos_kernel_export_mount_v2 *policy)
{
  __u64 boot_id[2];
  int mount_fd = -1;
  int grant_fd = -1;
  int result = -1;

  mount_fd = open_checked_map(MOUNT_MAP_PIN, "export_mounts",
                              sizeof(mount_id), sizeof(*policy),
                              AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS);
  grant_fd = open_checked_map(GRANT_MAP_PIN, "consumer_grants",
                              sizeof(struct aos_kernel_export_grant_key_v2),
                              sizeof(struct aos_kernel_export_grant_v2),
                              AOS_KERNEL_EXPORT_DENY_MAX_GRANTS);
  if (mount_fd < 0 || grant_fd < 0 || current_boot_id(boot_id) != 0 ||
      bpf_map_lookup_elem(mount_fd, &mount_id, policy) != 0 ||
      policy->version != AOS_KERNEL_EXPORT_DENY_VERSION ||
      policy->epoch == 0 || policy->reserved != 0 ||
      memcmp(policy->boot_id, boot_id, sizeof(boot_id)) != 0)
    goto out;

  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    if (inspect_link(program_names[i]) != 0)
      goto out;
  }
  result = 0;

out:
  if (mount_fd >= 0)
    close(mount_fd);
  if (grant_fd >= 0)
    close(grant_fd);
  return result;
}

static int validate_map(struct bpf_object *object, const char *name,
                        __u32 key_size, __u32 value_size, __u32 max_entries)
{
  struct bpf_map *map = bpf_object__find_map_by_name(object, name);

  return map != NULL && bpf_map__type(map) == BPF_MAP_TYPE_HASH &&
         bpf_map__key_size(map) == key_size &&
         bpf_map__value_size(map) == value_size &&
         bpf_map__max_entries(map) == max_entries &&
         bpf_map__map_flags(map) == BPF_F_RDONLY_PROG ? 0 : -1;
}

static int validate_object(void)
{
  struct bpf_object *object = bpf_object__open_file(
      AOS_KERNEL_EXPORT_DENY_OBJECT, NULL);
  int result = -1;

  if (object == NULL || libbpf_get_error(object) != 0)
    return -1;
  if (validate_map(object, "export_mounts", sizeof(__u64),
                   sizeof(struct aos_kernel_export_mount_v2),
                   AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS) != 0 ||
      validate_map(object, "consumer_grants",
                   sizeof(struct aos_kernel_export_grant_key_v2),
                   sizeof(struct aos_kernel_export_grant_v2),
                   AOS_KERNEL_EXPORT_DENY_MAX_GRANTS) != 0)
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
  bool mount_pinned = false;
  bool grant_pinned = false;
  struct bpf_map *mount_map;
  struct bpf_map *grant_map;
  struct aos_kernel_export_mount_v2 state = {
      .epoch = 1,
      .version = AOS_KERNEL_EXPORT_DENY_VERSION,
  };
  struct aos_kernel_export_mount_v2 observed;
  const char *failure_stage = "BPF object load";
  int result = -1;

  if (check_bpffs() != 0 || current_boot_id(state.boot_id) != 0)
    return -1;
  if (access(MOUNT_MAP_PIN, F_OK) == 0 || errno != ENOENT ||
      access(GRANT_MAP_PIN, F_OK) == 0 || errno != ENOENT) {
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
  if (object == NULL || libbpf_get_error(object) != 0 ||
      bpf_object__load(object) != 0)
    goto out;
  mount_map = bpf_object__find_map_by_name(object, "export_mounts");
  grant_map = bpf_object__find_map_by_name(object, "consumer_grants");
  if (mount_map == NULL || grant_map == NULL ||
      bpf_map_update_elem(bpf_map__fd(mount_map), &mount_id,
                          &state, BPF_NOEXIST) != 0)
    goto out;

  failure_stage = "LSM link attachment";
  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    struct bpf_program *program =
        bpf_object__find_program_by_name(object, program_names[i]);
    if (program == NULL)
      goto out;
    links[i] = bpf_program__attach_lsm(program);
    if (links[i] == NULL || libbpf_get_error(links[i]) != 0) {
      links[i] = NULL;
      goto out;
    }
  }

  failure_stage = "policy pinning";
  if (bpf_map__pin(mount_map, MOUNT_MAP_PIN) != 0)
    goto out;
  mount_pinned = true;
  if (bpf_map__pin(grant_map, GRANT_MAP_PIN) != 0)
    goto out;
  grant_pinned = true;
  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    char path[PATH_MAX];

    if (pin_path(path, sizeof(path), program_names[i]) != 0 ||
        bpf_link__pin(links[i], path) != 0)
      goto out;
    pinned[i] = true;
  }

  failure_stage = "pinned policy readback";
  if (inspect_installation(mount_id, &observed) != 0 ||
      memcmp(&state, &observed, sizeof(state)) != 0)
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
    if (grant_pinned)
      unlink(GRANT_MAP_PIN);
    if (mount_pinned)
      unlink(MOUNT_MAP_PIN);
    fprintf(stderr, "kernel-export-deny: installation failed at %s\n",
            failure_stage);
  }
  for (size_t i = 0; i < PROGRAM_COUNT; i++) {
    if (links[i] != NULL)
      bpf_link__destroy(links[i]);
  }
  if (object != NULL && libbpf_get_error(object) == 0)
    bpf_object__close(object);
  return result;
}

static int update_grant(__u64 mount_id, __u64 cgroup_id, __u64 ttl_ms)
{
  struct aos_kernel_export_mount_v2 policy;
  struct aos_kernel_export_grant_key_v2 key = {
      .mount_id = mount_id,
      .cgroup_id = cgroup_id,
  };
  struct aos_kernel_export_grant_v2 grant = {
      .state = AOS_KERNEL_EXPORT_GRANT_ACTIVE,
      .version = AOS_KERNEL_EXPORT_DENY_VERSION,
  };
  struct aos_kernel_export_grant_v2 observed;
  __u64 now;
  int grant_fd = -1;
  int result = -1;

  if (check_bpffs() != 0 || inspect_installation(mount_id, &policy) != 0 ||
      boot_time_ns(&now) != 0 || ttl_ms == 0 ||
      ttl_ms > MAX_GRANT_TTL_MS ||
      now > UINT64_MAX - ttl_ms * 1000000ULL)
    return -1;

  memcpy(grant.boot_id, policy.boot_id, sizeof(grant.boot_id));
  grant.epoch = policy.epoch;
  grant.expires_boot_ns = now + ttl_ms * 1000000ULL;
  grant_fd = open_checked_map(GRANT_MAP_PIN, "consumer_grants",
                              sizeof(key), sizeof(grant),
                              AOS_KERNEL_EXPORT_DENY_MAX_GRANTS);
  if (grant_fd < 0 ||
      bpf_map_update_elem(grant_fd, &key, &grant, BPF_ANY) != 0 ||
      bpf_map_lookup_elem(grant_fd, &key, &observed) != 0 ||
      memcmp(&grant, &observed, sizeof(grant)) != 0)
    goto out;
  result = 0;

out:
  if (grant_fd >= 0)
    close(grant_fd);
  return result;
}

static int revoke_grant(__u64 mount_id, __u64 cgroup_id)
{
  struct aos_kernel_export_mount_v2 policy;
  struct aos_kernel_export_mount_v2 observed_policy;
  struct aos_kernel_export_grant_key_v2 key = {
      .mount_id = mount_id,
      .cgroup_id = cgroup_id,
  };
  struct aos_kernel_export_grant_v2 grant;
  struct aos_kernel_export_grant_v2 observed_grant;
  int mount_fd = -1;
  int grant_fd = -1;
  int result = -1;

  if (check_bpffs() != 0 || inspect_installation(mount_id, &policy) != 0 ||
      policy.epoch == UINT64_MAX)
    return -1;
  mount_fd = open_checked_map(MOUNT_MAP_PIN, "export_mounts",
                              sizeof(mount_id), sizeof(policy),
                              AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS);
  grant_fd = open_checked_map(GRANT_MAP_PIN, "consumer_grants",
                              sizeof(key), sizeof(grant),
                              AOS_KERNEL_EXPORT_DENY_MAX_GRANTS);
  if (mount_fd < 0 || grant_fd < 0 ||
      bpf_map_lookup_elem(grant_fd, &key, &grant) != 0)
    goto out;

  /* Epoch first: even a later failure to mark the row cannot keep it live. */
  policy.epoch++;
  if (bpf_map_update_elem(mount_fd, &mount_id, &policy, BPF_EXIST) != 0 ||
      bpf_map_lookup_elem(mount_fd, &mount_id, &observed_policy) != 0 ||
      memcmp(&policy, &observed_policy, sizeof(policy)) != 0)
    goto out;

  grant.state = AOS_KERNEL_EXPORT_GRANT_REVOKED;
  if (bpf_map_update_elem(grant_fd, &key, &grant, BPF_EXIST) != 0 ||
      bpf_map_lookup_elem(grant_fd, &key, &observed_grant) != 0 ||
      memcmp(&grant, &observed_grant, sizeof(grant)) != 0)
    goto out;
  result = 0;

out:
  if (mount_fd >= 0)
    close(mount_fd);
  if (grant_fd >= 0)
    close(grant_fd);
  return result;
}

int main(int argc, char **argv)
{
  struct aos_kernel_export_mount_v2 policy;
  char *end = NULL;
  unsigned long long ttl_ms;
  int source_fd;
  int cgroup_fd;
  __u64 mount_id;
  __u64 cgroup_id;

  if (argc == 2 && strcmp(argv[1], "validate") == 0)
    return validate_object() == 0 ? 0 : 1;

  if ((argc != 3 && argc != 4 && argc != 5) ||
      (strcmp(argv[1], "install") != 0 &&
       strcmp(argv[1], "inspect") != 0 &&
       strcmp(argv[1], "grant") != 0 &&
       strcmp(argv[1], "revoke") != 0)) {
    fprintf(stderr,
            "usage: aos-sandbox-kernel-export-deny validate\n"
            "       aos-sandbox-kernel-export-deny install|inspect FD\n"
            "       aos-sandbox-kernel-export-deny grant FD CGROUP_FD TTL_MS\n"
            "       aos-sandbox-kernel-export-deny revoke FD CGROUP_FD\n");
    return 2;
  }
  if (geteuid() != 0 || parse_fd(argv[2], &source_fd) != 0 ||
      mount_id_from_fd(source_fd, &mount_id) != 0)
    return 2;

  if (argc == 3 && strcmp(argv[1], "install") == 0)
    return install(mount_id) == 0 ? 0 : 1;
  if (argc == 3 && strcmp(argv[1], "inspect") == 0) {
    if (check_bpffs() == 0 && inspect_installation(mount_id, &policy) == 0)
      return 0;
    fprintf(stderr, "kernel-export-deny: physical policy readback failed\n");
    return 1;
  }

  if (argc < 4 || parse_fd(argv[3], &cgroup_fd) != 0 ||
      cgroup_id_from_fd(cgroup_fd, &cgroup_id) != 0)
    return 2;
  if (argc == 4 && strcmp(argv[1], "revoke") == 0)
    return revoke_grant(mount_id, cgroup_id) == 0 ? 0 : 1;
  if (argc != 5 || strcmp(argv[1], "grant") != 0)
    return 2;

  errno = 0;
  ttl_ms = strtoull(argv[4], &end, 10);
  if (errno != 0 || end == argv[4] || *end != '\0' ||
      ttl_ms == 0 || ttl_ms > MAX_GRANT_TTL_MS)
    return 2;
  return update_grant(mount_id, cgroup_id, ttl_ms) == 0 ? 0 : 1;
}
