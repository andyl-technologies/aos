// SPDX-License-Identifier: Apache-2.0
/* Executes the production loader's RTM_GETLINK parser against real loopback. */

#define main aos_network_loader_program_main
#ifndef AOS_NETWORK_LOADER_SOURCE
#define AOS_NETWORK_LOADER_SOURCE                                            \
  "../../pkgs/security/aos-sandbox-network-lease-gate-loader.c"
#endif
#include AOS_NETWORK_LOADER_SOURCE
#undef main

int main(void)
{
  struct linkinfo_fixture {
    struct rtattr outer;
    struct rtattr first_kind;
    char first_name[RTA_ALIGN(5)];
    struct rtattr second_kind;
    char second_name[RTA_ALIGN(5)];
  } linkinfo;
  struct link_identity loopback;
  union netlink_response_buffer truncated;
  struct nlmsgerr malformed_error;
  __u32 port_id = 42;

  if (read_link("lo", &loopback) != 0 || loopback.ifindex == 0)
    return 1;
  memset(&truncated, 0, sizeof(truncated));
  truncated.alignment.nlmsg_len = NLMSG_HDRLEN;
  truncated.alignment.nlmsg_type = NLMSG_ERROR;
  truncated.alignment.nlmsg_seq = 1;
  truncated.alignment.nlmsg_pid = port_id;
  if (parse_link_response(&truncated, NLMSG_HDRLEN, port_id, &loopback) == 0)
    return 2;
  memset(&truncated, 0, sizeof(truncated));
  truncated.alignment.nlmsg_len = NLMSG_HDRLEN;
  truncated.alignment.nlmsg_type = RTM_NEWLINK;
  truncated.alignment.nlmsg_seq = 1;
  truncated.alignment.nlmsg_pid = port_id;
  if (parse_link_response(&truncated, NLMSG_HDRLEN, port_id, &loopback) == 0)
    return 3;
  if (parse_link_response(&truncated, sizeof(truncated.bytes) + 1, port_id,
                          &loopback) == 0)
    return 4;
  memset(&truncated, 0, sizeof(truncated));
  truncated.alignment.nlmsg_len = NLMSG_LENGTH(sizeof(malformed_error));
  truncated.alignment.nlmsg_type = NLMSG_ERROR;
  truncated.alignment.nlmsg_seq = 1;
  truncated.alignment.nlmsg_pid = port_id;
  memset(&malformed_error, 0, sizeof(malformed_error));
  malformed_error.error = INT_MIN;
  memcpy(NLMSG_DATA(&truncated.alignment), &malformed_error,
         sizeof(malformed_error));
  if (parse_link_response(&truncated, truncated.alignment.nlmsg_len, port_id,
                          &loopback) == 0)
    return 5;

  memset(&linkinfo, 0, sizeof(linkinfo));
  linkinfo.outer.rta_len = RTA_LENGTH(RTA_ALIGN(RTA_LENGTH(5)));
  linkinfo.first_kind.rta_len = RTA_LENGTH(5);
  linkinfo.first_kind.rta_type = IFLA_INFO_KIND;
  memcpy(linkinfo.first_name, "veth", 5);
  if (!link_info_is_veth(&linkinfo.outer))
    return 6;
  linkinfo.outer.rta_len = sizeof(linkinfo);
  linkinfo.second_kind.rta_len = RTA_LENGTH(5);
  linkinfo.second_kind.rta_type = IFLA_INFO_KIND;
  memcpy(linkinfo.second_name, "veth", 5);
  if (link_info_is_veth(&linkinfo.outer))
    return 7;
  memset(&linkinfo.second_kind, 0,
         sizeof(linkinfo.second_kind) + sizeof(linkinfo.second_name));
  ((unsigned char *)&linkinfo.second_kind)[0] = 0xff;
  linkinfo.outer.rta_len = RTA_LENGTH(RTA_ALIGN(RTA_LENGTH(5))) + 1;
  if (link_info_is_veth(&linkinfo.outer))
    return 8;
  return 0;
}
