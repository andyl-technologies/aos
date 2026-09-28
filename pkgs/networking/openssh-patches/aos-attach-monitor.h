/* Copyright 2026 Andyl, Inc. SPDX-License-Identifier: ISC
 * Fixed AOS attach custody prerequisite; not an I/O authorization interface.
 */
#ifndef AOS_ATTACH_MONITOR_H
#define AOS_ATTACH_MONITOR_H

/* These values extend only the private connection owned by this monitor. */
#define AOS_ATTACH_READY_REQUEST 118
#define AOS_ATTACH_READY_ANSWER 119
#define AOS_ATTACH_RELAY_REQUEST 116
#define AOS_ATTACH_RELAY_ANSWER 117
#define AOS_ATTACH_TERMINAL_REQUEST 120
#define AOS_ATTACH_TERMINAL_ANSWER 121
#define AOS_ATTACH_CONTROL_REQUEST 122
#define AOS_ATTACH_CONTROL_ANSWER 123

struct ssh;
struct sshbuf;

void aos_attach_monitor_capture(const unsigned char *, size_t,
    const unsigned char *, size_t, const unsigned char *, size_t,
    const unsigned char *, size_t, uid_t, gid_t);
void aos_attach_monitor_complete(void);
void aos_attach_monitor_parent(pid_t, int);
void aos_attach_monitor_child(int);
int aos_attach_monitor_connect_guest(void);
int aos_attach_monitor_relay(struct ssh *, int, struct sshbuf *);
int aos_attach_monitor_terminal(struct ssh *, int, struct sshbuf *);
int aos_attach_original_waitstatus(void);
int aos_attach_monitor_control(struct ssh *, int, struct sshbuf *);
int aos_attach_original_signal(int);
int aos_attach_original_resize(unsigned int, unsigned int, unsigned int, unsigned int);
int aos_attach_original_pty(const char *, unsigned int, unsigned int,
    unsigned int, unsigned int, const unsigned char *, size_t);

#endif
