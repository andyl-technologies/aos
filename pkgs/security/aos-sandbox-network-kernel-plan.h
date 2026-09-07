/*
 * Architecture-neutral byte layout for a canonical Network kernel plan.
 *
 * Consumers decode individual big-endian fields from bytes. They must not
 * cast an untrusted packet to these structs; the declarations and assertions
 * pin offsets for independent C and Rust codec conformance tests.
 */
#ifndef AOS_SANDBOX_NETWORK_KERNEL_PLAN_H
#define AOS_SANDBOX_NETWORK_KERNEL_PLAN_H

#include <linux/types.h>

#define AOS_NETWORK_KERNEL_PLAN_VERSION 1U
#define AOS_NETWORK_KERNEL_PLAN_FIXED_BYTES 392U
#define AOS_NETWORK_KERNEL_PLAN_ADDRESS_PAIR_BYTES 36U
#define AOS_NETWORK_KERNEL_PLAN_ROUTE_BYTES 36U
#define AOS_NETWORK_KERNEL_PLAN_ENDPOINT_BYTES 52U
#define AOS_NETWORK_KERNEL_PLAN_FLOW_BYTES 28U
#define AOS_NETWORK_KERNEL_PLAN_MAX_BYTES (512U * 1024U)
#define AOS_NETWORK_KERNEL_PLAN_MAX_ADDRESS_PAIRS 2U
#define AOS_NETWORK_KERNEL_PLAN_MAX_ROUTES 256U
#define AOS_NETWORK_KERNEL_PLAN_MAX_ENDPOINTS 256U
#define AOS_NETWORK_KERNEL_PLAN_MAX_FLOWS_PER_ENDPOINT 64U

enum aos_network_kernel_action_v1 {
  AOS_NETWORK_KERNEL_ACTION_PREPARE = 1,
};

enum aos_network_namespace_publication_requirement_v1 {
  AOS_NETWORK_NAMESPACE_PUBLICATION_RETAINED_DESCRIPTOR_TARGET = 1,
};

struct aos_network_kernel_plan_header_v1 {
  __u8 magic[8];
  __be16 version;
  __u8 action;
  __u8 publication_requirement;
  __be32 total_bytes;
};

struct aos_network_kernel_assignment_v1 {
  __u8 sandbox_id[16];
  __u8 incarnation_id[16];
  __be64 assignment_epoch;
  __be64 desired_generation;
  __u8 assignment_digest[32];
};

struct aos_network_kernel_plan_fixed_v1 {
  struct aos_network_kernel_plan_header_v1 header;
  struct aos_network_kernel_assignment_v1 assignment;
  __u8 network_handle[32];
  __be64 allocation_generation;
  __u8 network_kind;
  __u8 veth_present;
  __u8 lease_gate_present;
  __u8 reserved0;
  __be32 mtu;
  __u8 host_interface_name[16];
  __u8 sandbox_interface_name[16];
  __u8 host_mac[6];
  __u8 sandbox_mac[6];
  __u8 reserved1[4];
  __u8 profile_digest[32];
  __u8 packet_program_digest[32];
  __u8 enforcement_program_digest[32];
  __u8 lease_gate_program_digest[32];
  __u8 namespace_plan_digest[32];
  __u8 policy_program_digest[32];
  __be16 address_pair_count;
  __be16 route_count;
  __be16 endpoint_count;
  __u8 reserved2[2];
};

_Static_assert(sizeof(struct aos_network_kernel_plan_header_v1) == 16,
               "Network kernel-plan header ABI changed");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_header_v1,
                                  version) == 8,
               "Network kernel-plan version moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_header_v1,
                                  action) == 10,
               "Network kernel-plan action moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_header_v1,
                                  publication_requirement) == 11,
               "Network kernel-plan publication requirement moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_header_v1,
                                  total_bytes) == 12,
               "Network kernel-plan length moved");

_Static_assert(sizeof(struct aos_network_kernel_assignment_v1) == 80,
               "Network kernel-plan assignment ABI changed");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_assignment_v1,
                                  assignment_epoch) == 32,
               "Network kernel-plan assignment epoch moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_assignment_v1,
                                  desired_generation) == 40,
               "Network kernel-plan desired generation moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_assignment_v1,
                                  assignment_digest) == 48,
               "Network kernel-plan assignment digest moved");

_Static_assert(sizeof(struct aos_network_kernel_plan_fixed_v1) ==
                   AOS_NETWORK_KERNEL_PLAN_FIXED_BYTES,
               "Network kernel-plan fixed ABI changed");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  assignment) == 16,
               "Network kernel-plan assignment moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  network_handle) == 96,
               "Network kernel-plan handle moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  allocation_generation) == 128,
               "Network kernel-plan allocation generation moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  network_kind) == 136,
               "Network kernel-plan kind moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  mtu) == 140,
               "Network kernel-plan MTU moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  host_interface_name) == 144,
               "Network kernel-plan host name moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  sandbox_interface_name) == 160,
               "Network kernel-plan sandbox name moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  host_mac) == 176,
               "Network kernel-plan host MAC moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  sandbox_mac) == 182,
               "Network kernel-plan sandbox MAC moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  profile_digest) == 192,
               "Network kernel-plan profile digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  packet_program_digest) == 224,
               "Network kernel-plan packet digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  enforcement_program_digest) == 256,
               "Network kernel-plan enforcement digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  lease_gate_program_digest) == 288,
               "Network kernel-plan gate digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  namespace_plan_digest) == 320,
               "Network kernel-plan namespace digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  policy_program_digest) == 352,
               "Network kernel-plan policy digest moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  address_pair_count) == 384,
               "Network kernel-plan address count moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  route_count) == 386,
               "Network kernel-plan route count moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  endpoint_count) == 388,
               "Network kernel-plan endpoint count moved");
_Static_assert(__builtin_offsetof(struct aos_network_kernel_plan_fixed_v1,
                                  reserved2) == 390,
               "Network kernel-plan final reserved bytes moved");

#endif
