/*
 * Versioned map ABI for the fixed sandbox network ownership-lease gate.
 *
 * The privileged Network worker owns construction, verification, pinning, and
 * serialized updates.  Callers never supply these structures directly.
 */
#ifndef AOS_SANDBOX_NETWORK_LEASE_GATE_H
#define AOS_SANDBOX_NETWORK_LEASE_GATE_H

#include <linux/types.h>

#define AOS_NETWORK_LEASE_GATE_FORMAT_VERSION 2U
#define AOS_NETWORK_LEASE_GATE_PROVENANCE_VERSION 1U
#define AOS_NETWORK_LEASE_GATE_BINDING_KEY 0U
#define AOS_NETWORK_LEASE_GATE_STATE_KEY 0U

struct aos_network_digest_v1 {
  __u64 words[4];
};

struct aos_network_boot_id_v1 {
  __u64 words[2];
};

struct aos_network_mac_address_v1 {
  __u8 octets[6];
};

/* Frozen before either packet hook is attached. */
struct aos_network_lease_binding_v1 {
  __u64 assignment_epoch;
  __u64 allocation_generation;
  __u64 namespace_device;
  __u64 namespace_inode;
  __u32 format_version;
  __u32 host_ifindex;
  __u32 peer_ifindex;
  __u32 reserved;
  __u32 provenance_version;
  __u32 ingress_program_id;
  __u32 egress_program_id;
  __u32 provenance_reserved;
  struct aos_network_digest_v1 network_handle;
  struct aos_network_digest_v1 assignment_digest;
  struct aos_network_digest_v1 gate_object_digest;
  struct aos_network_boot_id_v1 kernel_boot_id;
  struct aos_network_mac_address_v1 host_mac;
  struct aos_network_mac_address_v1 peer_mac;
  __u8 reserved_tail[4];
};

struct aos_network_direction_lease_v1 {
  __u64 assignment_epoch;
  __u64 lease_generation;
  __u64 deadline_boottime_nanoseconds;
  __u32 format_version;
  __u32 armed;
  struct aos_network_digest_v1 assignment_digest;
  struct aos_network_digest_v1 lease_digest;
};

/*
 * One update replaces both directions together in the production path.  The
 * per-direction representation lets observation prove both hooks and lets
 * corruption of either direction fail closed independently.
 */
struct aos_network_lease_state_v1 {
  __u32 format_version;
  __u32 reserved;
  struct aos_network_direction_lease_v1 ingress;
  struct aos_network_direction_lease_v1 egress;
};

_Static_assert(sizeof(struct aos_network_digest_v1) == 32,
               "network digest ABI changed");
_Static_assert(sizeof(struct aos_network_boot_id_v1) == 16,
               "network boot ID ABI changed");
_Static_assert(sizeof(struct aos_network_mac_address_v1) == 6,
               "network MAC address ABI changed");
_Static_assert(sizeof(struct aos_network_lease_binding_v1) == 192,
               "network lease binding ABI changed");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  assignment_epoch) == 0,
               "network lease binding assignment epoch moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  allocation_generation) == 8,
               "network lease binding allocation generation moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  namespace_device) == 16,
               "network lease binding namespace device moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  namespace_inode) == 24,
               "network lease binding namespace inode moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  format_version) == 32,
               "network lease binding version moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  host_ifindex) == 36,
               "network lease binding host ifindex moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  peer_ifindex) == 40,
               "network lease binding peer ifindex moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  reserved) == 44,
               "network lease binding reserved word moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  provenance_version) == 48,
               "network lease binding provenance version moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  ingress_program_id) == 52,
               "network lease binding ingress program ID moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  egress_program_id) == 56,
               "network lease binding egress program ID moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  provenance_reserved) == 60,
               "network lease binding provenance reserved word moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  network_handle) == 64,
               "network lease binding handle moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  assignment_digest) == 96,
               "network lease binding assignment digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  gate_object_digest) == 128,
               "network lease binding gate object digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  kernel_boot_id) == 160,
               "network lease binding boot ID moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  host_mac) == 176,
               "network lease binding host MAC moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  peer_mac) == 182,
               "network lease binding peer MAC moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_binding_v1,
                                  reserved_tail) == 188,
               "network lease binding reserved tail moved");
_Static_assert(sizeof(struct aos_network_direction_lease_v1) == 96,
               "network direction lease ABI changed");
_Static_assert(__builtin_offsetof(struct aos_network_direction_lease_v1,
                                  assignment_epoch) == 0,
               "network direction assignment epoch moved");
_Static_assert(__builtin_offsetof(struct aos_network_direction_lease_v1,
                                  lease_generation) == 8,
               "network direction lease generation moved");
_Static_assert(__builtin_offsetof(struct aos_network_direction_lease_v1,
                                  deadline_boottime_nanoseconds) == 16,
               "network direction deadline moved");
_Static_assert(__builtin_offsetof(struct aos_network_direction_lease_v1,
                                  format_version) == 24,
               "network direction version moved");
_Static_assert(__builtin_offsetof(struct aos_network_direction_lease_v1,
                                  armed) == 28,
               "network direction armed field moved");
_Static_assert(__builtin_offsetof(struct aos_network_direction_lease_v1,
                                  assignment_digest) == 32,
               "network direction assignment digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_direction_lease_v1,
                                  lease_digest) == 64,
               "network direction lease digest moved");
_Static_assert(sizeof(struct aos_network_lease_state_v1) == 200,
               "network lease state ABI changed");
_Static_assert(__builtin_offsetof(struct aos_network_lease_state_v1,
                                  format_version) == 0,
               "network lease state version moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_state_v1,
                                  reserved) == 4,
               "network lease state reserved word moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_state_v1,
                                  ingress) == 8,
               "network lease state ingress moved");
_Static_assert(__builtin_offsetof(struct aos_network_lease_state_v1,
                                  egress) == 104,
               "network lease state egress moved");

#endif
