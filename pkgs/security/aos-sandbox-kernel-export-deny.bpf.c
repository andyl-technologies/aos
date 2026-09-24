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
  __type(value, struct aos_kernel_export_deny_v1);
} denied_mounts SEC(".maps");

static __always_inline int deny_file(const struct file *file, int ret)
{
  struct vfsmount *vfsmount = 0;
  struct mount *mount;
  const struct aos_kernel_export_deny_v1 *state;
  __u64 mount_id = 0;

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

  state = bpf_map_lookup_elem(&denied_mounts, &mount_id);
  if (state == 0)
    return ret;

  /* A malformed entry remains a denial, including across ABI upgrades. */
  return -EACCES;
}

SEC("lsm/file_open")
int BPF_PROG(aos_deny_open, struct file *file, int ret)
{
  return deny_file(file, ret);
}

SEC("lsm/file_permission")
int BPF_PROG(aos_deny_access, struct file *file, int mask, int ret)
{
  (void)mask;
  return deny_file(file, ret);
}

SEC("lsm/mmap_file")
int BPF_PROG(aos_deny_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
  (void)reqprot;
  (void)prot;
  (void)flags;
  return deny_file(file, ret);
}

SEC("lsm/file_mprotect")
int BPF_PROG(aos_deny_mprot, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
  struct file *file = 0;

  (void)reqprot;
  (void)prot;
  if (ret != 0 || vma == 0)
    return ret;
  if (bpf_core_read(&file, sizeof(file), &vma->vm_file) != 0)
    return -EACCES;
  return deny_file(file, ret);
}

SEC("lsm/file_lock")
int BPF_PROG(aos_deny_lock, struct file *file, unsigned int cmd, int ret)
{
  (void)cmd;
  return deny_file(file, ret);
}

SEC("lsm/file_receive")
int BPF_PROG(aos_deny_recv, struct file *file, int ret)
{
  return deny_file(file, ret);
}

SEC("lsm/file_fcntl")
int BPF_PROG(aos_deny_fcntl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
  (void)cmd;
  (void)arg;
  return deny_file(file, ret);
}

SEC("lsm/file_ioctl")
int BPF_PROG(aos_deny_ioctl, struct file *file, unsigned int cmd,
             unsigned long arg, int ret)
{
  (void)cmd;
  (void)arg;
  return deny_file(file, ret);
}

SEC("lsm/file_ioctl_compat")
int BPF_PROG(aos_deny_iocmp, struct file *file,
             unsigned int cmd, unsigned long arg, int ret)
{
  (void)cmd;
  (void)arg;
  return deny_file(file, ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
