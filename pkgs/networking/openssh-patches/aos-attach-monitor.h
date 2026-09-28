/* Copyright 2026 Andyl, Inc. SPDX-License-Identifier: ISC
 * Fixed AOS attach custody prerequisite; not an I/O authorization interface.
 */
#ifndef AOS_ATTACH_MONITOR_H
#define AOS_ATTACH_MONITOR_H

/* These values extend only the private connection owned by this monitor. */
#define AOS_ATTACH_READY_REQUEST 114
#define AOS_ATTACH_READY_ANSWER 115

void aos_attach_monitor_capture(const unsigned char *, size_t,
    const unsigned char *, size_t, const unsigned char *, size_t,
    const unsigned char *, size_t, uid_t, gid_t);
void aos_attach_monitor_complete(void);
void aos_attach_monitor_parent(pid_t, int);
void aos_attach_monitor_child(int);

#endif
