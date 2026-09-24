/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only */
#ifndef AOS_SANDBOX_KERNEL_EXPORT_DENY_H
#define AOS_SANDBOX_KERNEL_EXPORT_DENY_H

#include <linux/types.h>

#define AOS_KERNEL_EXPORT_DENY_VERSION 1U
#define AOS_KERNEL_EXPORT_DENY_MAX_MOUNTS 1024U

/* Presence alone denies; the version and initial epoch support readback. */
struct aos_kernel_export_deny_v1 {
  __u64 epoch;
  __u32 version;
  __u32 reserved;
};

_Static_assert(sizeof(struct aos_kernel_export_deny_v1) == 16,
               "kernel export deny map ABI changed");

#endif
