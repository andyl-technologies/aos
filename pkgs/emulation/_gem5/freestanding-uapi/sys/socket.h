/* SPDX-License-Identifier: MIT */
#ifndef CRUCIBLE_FREESTANDING_LINUX_SOCKADDR_H
#define CRUCIBLE_FREESTANDING_LINUX_SOCKADDR_H

/* Linux's sanitized if.h includes this common socket ABI normally supplied by
 * libc. A freestanding syscall caller needs the actual layout, not libc. */
struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

_Static_assert(sizeof(struct sockaddr) == 16, "Linux sockaddr ABI extent");

#endif
