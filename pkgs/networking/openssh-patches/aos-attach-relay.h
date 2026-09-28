/* Copyright 2026 Andyl, Inc. SPDX-License-Identifier: ISC */
#ifndef AOS_ATTACH_RELAY_H
#define AOS_ATTACH_RELAY_H

void aos_attach_relay_before_fork(void);
void aos_attach_relay_parent(pid_t);
void aos_attach_relay_child(void);
void aos_attach_internal_relay(void) __attribute__((noreturn));

#endif
