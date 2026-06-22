#include <linux/bpf.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65535);
  __type(key, __u32);
  __type(value, __u8);
} bind_ports SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65535);
  __type(key, __u32);
  __type(value, __u8);
} connect_ports SEC(".maps");

static __always_inline int allow_tcp_port(struct bpf_sock_addr *ctx, void *ports)
{
  __u32 port;
  __u8 *allowed;

  if (ctx->protocol != IPPROTO_TCP)
    return 1;

  port = ctx->user_port;
  allowed = bpf_map_lookup_elem(ports, &port);
  return allowed != 0;
}

SEC("cgroup/bind4")
int aos_bind4(struct bpf_sock_addr *ctx)
{
  return allow_tcp_port(ctx, &bind_ports);
}

SEC("cgroup/bind6")
int aos_bind6(struct bpf_sock_addr *ctx)
{
  return allow_tcp_port(ctx, &bind_ports);
}

SEC("cgroup/connect4")
int aos_connect4(struct bpf_sock_addr *ctx)
{
  return allow_tcp_port(ctx, &connect_ports);
}

SEC("cgroup/connect6")
int aos_connect6(struct bpf_sock_addr *ctx)
{
  return allow_tcp_port(ctx, &connect_ports);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
