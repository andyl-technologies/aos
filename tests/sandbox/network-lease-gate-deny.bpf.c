// SPDX-License-Identifier: Apache-2.0

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

struct gate_context_observation {
  __u32 ifindex;
  __u32 ingress_ifindex;
  __u64 boottime_nanoseconds;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct gate_context_observation);
} ingress_context SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct gate_context_observation);
} egress_context SEC(".maps");

static __always_inline void observe_context(
    struct __sk_buff *packet, void *observations)
{
  struct gate_context_observation observation = {
      .ifindex = packet->ifindex,
      .ingress_ifindex = packet->ingress_ifindex,
      .boottime_nanoseconds = bpf_ktime_get_boot_ns(),
  };
  __u32 key = 0;

  bpf_map_update_elem(observations, &key, &observation, BPF_ANY);
}

SEC("tcx/ingress")
int observe_ingress(struct __sk_buff *packet)
{
  observe_context(packet, &ingress_context);
  return TCX_NEXT;
}

SEC("tcx/egress")
int observe_egress(struct __sk_buff *packet)
{
  observe_context(packet, &egress_context);
  return TCX_NEXT;
}

SEC("tcx/ingress")
int deny_ingress(struct __sk_buff *packet)
{
  (void)packet;
  return TCX_DROP;
}

SEC("tcx/egress")
int deny_egress(struct __sk_buff *packet)
{
  (void)packet;
  return TCX_DROP;
}

SEC("tcx/ingress")
int allow_ingress(struct __sk_buff *packet)
{
  (void)packet;
  return TCX_PASS;
}

SEC("tcx/egress")
int allow_egress(struct __sk_buff *packet)
{
  (void)packet;
  return TCX_PASS;
}

char LICENSE[] SEC("license") = "Apache-2.0";
