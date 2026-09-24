// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only

#include <linux/bpf.h>
#include <linux/errno.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "aos-sandbox-kernel-export-deny.h"

/* CO-RE relocates these fields against the running kernel's BTF. */
struct vfsmount {
  unsigned long opaque;
} __attribute__((preserve_access_index));

struct path {
  struct vfsmount *mnt;
} __attribute__((preserve_access_index));

struct file {
  struct path f_path;
  unsigned int f_mode;
} __attribute__((preserve_access_index));

struct mount {
  struct vfsmount mnt;
  __u64 mnt_id_unique;
} __attribute__((preserve_access_index));

struct vm_area_struct {
  struct file *vm_file;
} __attribute__((preserve_access_index));

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, __u64);
  __type(value, struct aos_kernel_export_mount_v2);
} export_mounts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, AOS_KERNEL_EXPORT_DENY_MAX_GRANTS);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, struct aos_kernel_export_grant_key_v2);
  __type(value, struct aos_kernel_export_grant_v2);
} consumer_grants SEC(".maps");

#define AOS_WRITE_BIT 2U

static __always_inline int deny_file(const struct file *file, int ret,
                                     int disallowed, int check_file_mode)
{
  struct vfsmount *vfsmount = 0;
  struct mount *mount;
  const struct aos_kernel_export_mount_v2 *mount_policy;
  const struct aos_kernel_export_grant_v2 *grant;
  struct aos_kernel_export_grant_key_v2 grant_key = {0};
  __u64 mount_id = 0;
  unsigned int mode = 0;

  if (ret != 0 || file == 0)
    return ret;

  if (bpf_core_read(&vfsmount, sizeof(vfsmount), &file->f_path.mnt) != 0 ||
      vfsmount == 0)
    return -EACCES;

  mount = (struct mount *)((char *)vfsmount -
                           bpf_core_field_offset(struct mount, mnt));
  if (bpf_core_read(&mount_id, sizeof(mount_id), &mount->mnt_id_unique) != 0 ||
      mount_id == 0)
    return -EACCES;

  mount_policy = bpf_map_lookup_elem(&export_mounts, &mount_id);
  if (mount_policy == 0)
    return ret;

  /* A grant only permits read-side use; it is not a writable mount lease. */
  if (disallowed ||
      (check_file_mode &&
       (bpf_core_read(&mode, sizeof(mode), &file->f_mode) != 0 ||
        (mode & AOS_WRITE_BIT) != 0)))
    return -EACCES;

  grant_key.mount_id = mount_id;
  grant_key.cgroup_id = bpf_get_current_cgroup_id();
  if (grant_key.cgroup_id == 0)
    return -EACCES;

  grant = bpf_map_lookup_elem(&consumer_grants, &grant_key);
  if (grant == 0 || mount_policy->version != AOS_KERNEL_EXPORT_DENY_VERSION ||
      mount_policy->reserved != 0 || mount_policy->epoch == 0 ||
      grant->version != AOS_KERNEL_EXPORT_DENY_VERSION ||
      grant->state != AOS_KERNEL_EXPORT_GRANT_ACTIVE ||
      grant->epoch != mount_policy->epoch ||
      grant->boot_id[0] != mount_policy->boot_id[0] ||
      grant->boot_id[1] != mount_policy->boot_id[1] ||
      grant->expires_boot_ns <= bpf_ktime_get_boot_ns())
    return -EACCES;

  return ret;
}

SEC("lsm/file_open")
int BPF_PROG(aos_deny_open, struct file *file, int ret)
{
  return deny_file(file, ret, 0, 1);
}

SEC("lsm/file_permission")
int BPF_PROG(aos_deny_access, struct file *file, int mask, int ret)
{
  return deny_file(file, ret, (mask & AOS_WRITE_BIT) != 0, 0);
}

SEC("lsm/mmap_file")
int BPF_PROG(aos_deny_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
  (void)flags;
  return deny_file(file, ret, ((reqprot | prot) & AOS_WRITE_BIT) != 0, 0);
}

SEC("lsm/file_mprotect")
int BPF_PROG(aos_deny_mprot, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
  struct file *file = 0;

  if (ret != 0 || vma == 0)
    return ret;
  if (bpf_core_read(&file, sizeof(file), &vma->vm_file) != 0)
    return -EACCES;
  return deny_file(file, ret, ((reqprot | prot) & AOS_WRITE_BIT) != 0, 0);
}

SEC("lsm/file_lock")
int BPF_PROG(aos_deny_lock, struct file *file, unsigned int cmd, int ret)
{
  (void)cmd;
  return deny_file(file, ret, 1, 0);
}

SEC("lsm/file_receive")
int BPF_PROG(aos_deny_recv, struct file *file, int ret)
{
  return deny_file(file, ret, 0, 1);
}

SEC("lsm/file_fcntl")
int BPF_PROG(aos_deny_fcntl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
  (void)cmd;
  (void)arg;
  return deny_file(file, ret, 1, 0);
}

SEC("lsm/file_ioctl")
int BPF_PROG(aos_deny_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
  (void)cmd;
  (void)arg;
  return deny_file(file, ret, 1, 0);
}

SEC("lsm/file_ioctl_compat")
int BPF_PROG(aos_deny_iocmp, struct file *file,
             unsigned int cmd, unsigned long arg, int ret)
{
  (void)cmd;
  (void)arg;
  return deny_file(file, ret, 1, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
