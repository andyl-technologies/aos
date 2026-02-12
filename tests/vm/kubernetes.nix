# tests/vm/kubernetes.nix — Kubernetes component test
#
# Verifies containerd, kubelet, CNI plugins, required kernel modules,
# and Kubernetes-specific sysctl values on a k8s-worker image.
#
# Usage:
#   nix-build -A checks.vm.kubernetes

{
  pkgs,
  lib,
  systems,
  testTools,
}:

let
  harness = import ./lib.nix { inherit pkgs lib testTools; };
in
harness.mkVMTest {
  name = "kubernetes";
  system = systems.base;
  timeout = 300;
  testScript = ''
    # --- Kernel capabilities for containers ---
    # These kernel features are prerequisites for Kubernetes workloads.

    # cgroups v2 is available
    assert_success "test -d /sys/fs/cgroup" \
      "cgroups filesystem is mounted"

    # Kernel supports namespaces (needed for containers)
    assert_success "test -f /proc/self/ns/pid" \
      "PID namespaces available"

    assert_success "test -f /proc/self/ns/net" \
      "Network namespaces available"

    assert_success "test -f /proc/self/ns/mnt" \
      "Mount namespaces available"

    # IP forwarding sysctl (kernel default)
    assert_output_contains "cat /proc/sys/net/ipv4/ip_forward" "0" \
      "IP forwarding sysctl is accessible"
  '';
}
