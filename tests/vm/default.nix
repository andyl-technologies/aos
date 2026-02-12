# tests/vm/default.nix — VM integration test suite
#
# Single-VM tests that boot an AOS image in QEMU and verify system
# properties via virtio-serial guest agent.
#
# Available tests:
#   boot         — System boots to multi-user, systemd healthy
#   immutability — Root read-only, /var writable, /etc overlay
#   security     — SELinux, audit, firewall, sysctl hardening
#   networking   — systemd-networkd, resolved, chrony, SSH
#   kubernetes   — containerd, kubelet, CNI, kernel modules
#   update       — Update mechanism, health checks, rollback

{
  pkgs,
  lib,
  systems,
  testTools,
}:

{
  boot = import ./boot.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  immutability = import ./immutability.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  security = import ./security.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  networking = import ./networking.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  kubernetes = import ./kubernetes.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
  update = import ./update.nix {
    inherit
      pkgs
      lib
      systems
      testTools
      ;
  };
}
