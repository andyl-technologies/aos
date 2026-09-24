/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
#ifndef AOS_SANDBOX_KERNEL_EXPORT_DENY_H
#define AOS_SANDBOX_KERNEL_EXPORT_DENY_H

#include <linux/types.h>

#define AOS_KERNEL_EXPORT_DENY_VERSION 2U
#define AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS 1024U
#define AOS_KERNEL_EXPORT_DENY_MAX_GRANTS 1024U
#define AOS_KERNEL_EXPORT_GRANT_ACTIVE 1U
#define AOS_KERNEL_EXPORT_GRANT_REVOKED 2U

/* A protected mount defaults to denial when its grant is absent or invalid. */
struct aos_kernel_export_mount_v2 {
  __u64 boot_id[2];
  __u64 epoch;
  __u32 version;
  __u32 reserved;
};

struct aos_kernel_export_grant_key_v2 {
  __u64 mount_id;
  __u64 cgroup_id;
};

struct aos_kernel_export_grant_v2 {
  __u64 boot_id[2];
  __u64 epoch;
  __u64 expires_boot_ns;
  __u32 state;
  __u32 version;
};

_Static_assert(sizeof(struct aos_kernel_export_mount_v2) == 32,
               "kernel export mount map ABI changed");
_Static_assert(sizeof(struct aos_kernel_export_grant_key_v2) == 16,
               "kernel export grant key ABI changed");
_Static_assert(sizeof(struct aos_kernel_export_grant_v2) == 40,
               "kernel export grant map ABI changed");

#endif
