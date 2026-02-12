# tests/vm/kubernetes.nix — Kubernetes component test
#
# Verifies containerd, kubelet, CNI plugins, required kernel modules,
# and Kubernetes-specific sysctl values on a k8s-worker image.
#
# Usage:
#   nix-build -A checks.vm.kubernetes

{ pkgs, lib, systems }:

let
  harness = import ./lib.nix { inherit pkgs lib; };
in
harness.mkVMTest {
  name = "kubernetes";
  system = systems.k8s-worker;
  testScript = ''
    # --- containerd ---
    assert_success "systemctl is-active containerd" \
      "containerd is active"

    assert_success "test -S /run/containerd/containerd.sock" \
      "containerd socket exists"

    # crictl can connect to the container runtime
    assert_success "crictl --runtime-endpoint unix:///run/containerd/containerd.sock version" \
      "crictl can query containerd"

    # --- kubelet ---
    # kubelet may not be fully healthy without an API server, but the
    # service should be active or in the process of activating.
    assert_success "systemctl is-active kubelet || systemctl is-activating kubelet" \
      "kubelet is active or activating"

    assert_success "test -f /var/lib/kubelet/config.yaml" \
      "kubelet config file exists"

    # --- CNI plugins ---
    assert_success "test -d /opt/cni/bin" \
      "CNI bin directory exists"

    assert_success "ls /opt/cni/bin/ | wc -l | grep -v '^0$'" \
      "CNI plugins are installed"

    # --- Kernel modules ---
    assert_success "lsmod | grep -q br_netfilter" \
      "br_netfilter kernel module is loaded"

    assert_success "lsmod | grep -q overlay" \
      "overlay kernel module is loaded"

    # --- Kubernetes sysctl values ---
    assert_output_contains "sysctl net.bridge.bridge-nf-call-iptables" "1" \
      "bridge-nf-call-iptables is enabled"

    assert_output_contains "sysctl net.ipv4.ip_forward" "1" \
      "IP forwarding is enabled"
  '';
}
