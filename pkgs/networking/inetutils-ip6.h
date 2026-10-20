/* SPDX-License-Identifier: GPL-3.0-or-later */
/* RFC 8200 IPv6 base header for Darwin SDKs without <netinet/ip6.h>. */
#ifndef AOS_INETUTILS_IP6_H
#define AOS_INETUTILS_IP6_H

#include <stdint.h>
#include <netinet/in.h>

struct ip6_hdr
{
  uint32_t ip6_flow;
  uint16_t ip6_plen;
  uint8_t ip6_nxt;
  uint8_t ip6_hlim;
  struct in6_addr ip6_src;
  struct in6_addr ip6_dst;
};

_Static_assert (sizeof (struct ip6_hdr) == 40, "IPv6 base header must be 40 bytes");

#endif
