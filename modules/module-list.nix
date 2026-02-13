# modules/module-list.nix — Registry of all AOS configuration modules
#
# This is the single entry point that enumerates every module in the system.
# The module evaluator imports this list and merges all declared options and
# config sections. Modules are evaluated in list order; later modules can
# override values set by earlier ones (no mkDefault/mkForce needed).
#
# To add a new module: append its path here and create the file.

[
  # --- Base ---
  ./base/build.nix
  ./base/system.nix
  ./base/boot.nix
  ./base/filesystems.nix
  ./base/networking.nix
  ./base/users.nix
  ./base/journald.nix
  ./base/kernel.nix
  ./base/swap.nix
  ./base/repart.nix
  ./base/sysupdate.nix
  ./base/kdump.nix

  # --- Security ---
  ./security/selinux.nix
  ./security/audit.nix
  ./security/hardening.nix
  ./security/firewall.nix
  ./security/ssh.nix
  ./security/fail2ban.nix
  ./security/verity.nix
  ./security/encryption.nix

  # --- Services ---
  ./services/ignition.nix
  ./services/update.nix
  ./services/gc.nix
  ./services/chrony.nix
  ./services/sssd.nix
  ./services/vault-agent.nix

  # --- Kubernetes ---
  ./kubernetes/containerd.nix
  ./kubernetes/kubelet.nix
  ./kubernetes/network.nix
  ./kubernetes/control-plane.nix
  ./kubernetes/node-problem-detector.nix

  # --- Monitoring ---
  ./monitoring/node-exporter.nix
  ./monitoring/alloy.nix
  ./monitoring/hardware.nix

  # Note: profiles (hardened, debug, minimal) are imported explicitly
  # by system variants, not listed here, since they set concrete values.
]
