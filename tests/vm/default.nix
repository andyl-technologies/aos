# tests/vm/default.nix — VM integration test suite
#
# Single-VM tests that boot an AOS image in QEMU and verify system
# properties via virtio-serial guest agent.
#
# Tests use the correct system variant for what they're testing:
#   boot               — Base boot fundamentals (systems.base)
#   immutability       — Filesystem layout (systems.base)
#   security           — Kernel sysctl hardening (systems.server)
#   networking         — Network interface/hostname (systems.server)
#   kubernetes         — k8s components: containerd, kubelet, CNI (systems.k8s-worker)
#   update             — Update mechanism, timers, health checks (systems.server)
#   services           — systemd, chrony, SSH (systems.server)
#   server-security    — Deep security: SSH, firewall, SELinux, audit (systems.server)
#   k8s-services       — Deep k8s: containerd, kubelet, networking, exporter (systems.k8s-worker)
#   k8s-control-plane  — Control plane config: kubeadm, etcd (systems.k8s-control-plane)
#   seed               — Seed server: nginx, nix-daemon, build orchestration (systems.seed)
#   validate           — Pre-flight syntax check of all check scripts (no QEMU)

{
  pkgs,
  lib,
  systems,
  testTools,
}:

let
  harness = import ../../lib/testing { inherit pkgs lib testTools; };

  # Collect all check modules for validation gate
  allChecks =
    let
      mkC = { inherit (harness) mkCheck mkCheckGroup; };
    in
    [
      (import ./checks/boot-basics.nix mkC)
      (import ./checks/kernel-security.nix mkC)
      (import ./checks/filesystem.nix mkC)
      (import ./checks/networking-base.nix mkC)
      (import ./checks/container-support.nix mkC)
      (import ./checks/systemd-basics.nix mkC)
      (import ./checks/ssh.nix mkC)
      (import ./checks/firewall.nix mkC)
      (import ./checks/hardening.nix mkC)
      (import ./checks/selinux.nix mkC)
      (import ./checks/audit.nix mkC)
      (import ./checks/chrony.nix mkC)
      (import ./checks/update-infra.nix mkC)
      (import ./checks/containerd.nix mkC)
      (import ./checks/kubelet.nix mkC)
      (import ./checks/k8s-networking.nix mkC)
      (import ./checks/node-exporter.nix mkC)
      (import ./checks/nginx.nix mkC)
      (import ./checks/nix-daemon.nix mkC)
      (import ./checks/seed.nix mkC)
    ];

  args = {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
in
{
  # --- Base variant tests ---
  boot = import ./boot.nix args;
  immutability = import ./immutability.nix args;

  # --- Server variant tests ---
  security = import ./security.nix args;
  networking = import ./networking.nix args;
  services = import ./services.nix args;
  update = import ./update.nix args;
  server-security = import ./server-security.nix args;

  # --- Seed variant tests ---
  seed = import ./seed.nix args;

  # --- Kubernetes variant tests ---
  kubernetes = import ./kubernetes.nix args;
  k8s-services = import ./k8s-services.nix args;
  k8s-control-plane = import ./k8s-control-plane.nix args;

  # --- Pre-flight validation (no QEMU, instant) ---
  validate = harness.validateChecks {
    inherit pkgs;
    checks = allChecks;
  };
}
