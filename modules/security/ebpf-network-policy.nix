##! Selects the package-owned cgroup eBPF network policy provider.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.aos-ebpf-net-policy];
}
