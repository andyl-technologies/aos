/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AOS_SANDBOX_KERNEL_EXPORT_DENY_H
#define AOS_SANDBOX_KERNEL_EXPORT_DENY_H

#include <linux/types.h>

#define AOS_KERNEL_EXPORT_DENY_VERSION 1U
#define AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS 1024U

/* The entry is deny-only. Its epoch records ordering but cannot grant access. */
struct aos_kernel_export_deny_v1 {
  __u64 epoch;
  __u32 version;
  __u32 reserved;
};

_Static_assert(sizeof(struct aos_kernel_export_deny_v1) == 16,
               "kernel export deny map ABI changed");

#endif
