// SPDX-License-Identifier: Apache-2.0

#include <linux/bpf.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>

#include "aos-sandbox-network-lease-gate.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, __u32);
  __type(value, struct aos_network_lease_binding_v1);
} binding SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __uint(map_flags, BPF_F_RDONLY_PROG);
  __type(key, __u32);
  __type(value, struct aos_network_lease_state_v1);
} lease_state SEC(".maps");

static __always_inline bool digest_equal(const struct aos_network_digest_v1 *left,
                                         const struct aos_network_digest_v1 *right)
{
  return left->words[0] == right->words[0] &&
         left->words[1] == right->words[1] &&
         left->words[2] == right->words[2] &&
         left->words[3] == right->words[3];
}

static __always_inline bool digest_present(const struct aos_network_digest_v1 *digest)
{
  return digest->words[0] != 0 || digest->words[1] != 0 ||
         digest->words[2] != 0 || digest->words[3] != 0;
}

static __always_inline bool boot_id_present(const struct aos_network_boot_id_v1 *boot_id)
{
  return boot_id->words[0] != 0 || boot_id->words[1] != 0;
}

static __always_inline bool mac_valid(const struct aos_network_mac_address_v1 *mac)
{
  bool present = mac->octets[0] != 0 || mac->octets[1] != 0 ||
                 mac->octets[2] != 0 || mac->octets[3] != 0 ||
                 mac->octets[4] != 0 || mac->octets[5] != 0;

  return present && (mac->octets[0] & 1) == 0;
}

static __always_inline bool mac_equal(const struct aos_network_mac_address_v1 *left,
                                      const struct aos_network_mac_address_v1 *right)
{
  return left->octets[0] == right->octets[0] &&
         left->octets[1] == right->octets[1] &&
         left->octets[2] == right->octets[2] &&
         left->octets[3] == right->octets[3] &&
         left->octets[4] == right->octets[4] &&
         left->octets[5] == right->octets[5];
}

static __always_inline bool binding_valid(const struct aos_network_lease_binding_v1 *expected,
                                          const struct __sk_buff *packet)
{
  return expected->format_version == AOS_NETWORK_LEASE_GATE_FORMAT_VERSION &&
         expected->provenance_version == AOS_NETWORK_LEASE_GATE_PROVENANCE_VERSION &&
         expected->ingress_program_id != 0 && expected->egress_program_id != 0 &&
         expected->ingress_program_id != expected->egress_program_id &&
         expected->reserved == 0 && expected->provenance_reserved == 0 &&
         expected->reserved_tail[0] == 0 &&
         expected->reserved_tail[1] == 0 && expected->reserved_tail[2] == 0 &&
         expected->reserved_tail[3] == 0 && expected->assignment_epoch != 0 &&
         expected->allocation_generation != 0 && expected->namespace_device != 0 &&
         expected->namespace_inode != 0 && expected->host_ifindex != 0 &&
         expected->peer_ifindex != 0 &&
         expected->host_ifindex == packet->ifindex &&
         digest_present(&expected->network_handle) &&
         digest_present(&expected->assignment_digest) &&
         digest_present(&expected->gate_object_digest) &&
         boot_id_present(&expected->kernel_boot_id) &&
         mac_valid(&expected->host_mac) && mac_valid(&expected->peer_mac) &&
         !mac_equal(&expected->host_mac, &expected->peer_mac);
}

static __always_inline int gate_packet(struct __sk_buff *packet, bool ingress)
{
  const struct aos_network_direction_lease_v1 *direction;
  const struct aos_network_lease_binding_v1 *expected;
  const struct aos_network_lease_state_v1 *state;
  __u32 key = AOS_NETWORK_LEASE_GATE_BINDING_KEY;

  expected = bpf_map_lookup_elem(&binding, &key);
  state = bpf_map_lookup_elem(&lease_state, &key);
  if (expected == NULL || state == NULL)
    return TCX_DROP;

  if (!binding_valid(expected, packet) ||
      state->format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      state->reserved != 0)
    return TCX_DROP;

  direction = ingress ? &state->ingress : &state->egress;
  if (direction->format_version != AOS_NETWORK_LEASE_GATE_FORMAT_VERSION ||
      direction->armed != 1 ||
      direction->assignment_epoch != expected->assignment_epoch ||
      !digest_equal(&direction->assignment_digest,
                    &expected->assignment_digest) ||
      !digest_present(&direction->lease_digest) ||
      direction->lease_generation == 0 ||
      direction->deadline_boottime_nanoseconds == 0 ||
      bpf_ktime_get_boot_ns() >= direction->deadline_boottime_nanoseconds)
    return TCX_DROP;

  /* Continue into the mandatory anti-spoof and endpoint-policy chain. */
  return TCX_NEXT;
}

SEC("tcx/ingress")
int aos_network_lease_ingress(struct __sk_buff *packet)
{
  return gate_packet(packet, true);
}

SEC("tcx/egress")
int aos_network_lease_egress(struct __sk_buff *packet)
{
  return gate_packet(packet, false);
}

char LICENSE[] SEC("license") = "Apache-2.0";
