# modules/module-list.nix — Registry of all AOS configuration modules
#
# This is the single entry point that enumerates every module in the system.
# The module evaluator imports this list and merges all declared options and
# config sections. Modules are evaluated in list order; later modules can
# override values set by earlier ones (no mkDefault/mkForce needed).
#
# To add a new module: append its path here and create the file.

[
  ./base/build.nix
  ./base/system.nix
  ./base/boot.nix
  ./base/filesystems.nix
  ./base/networking.nix
  ./base/users.nix
  ./security/selinux.nix
  ./security/audit.nix
  ./security/hardening.nix
  ./security/firewall.nix
  ./security/ssh.nix
  ./services/ignition.nix
  ./services/update.nix
  ./services/gc.nix
  ./services/chrony.nix
  ./kubernetes/containerd.nix
  ./kubernetes/kubelet.nix
  ./kubernetes/network.nix
  ./kubernetes/control-plane.nix
  ./monitoring/node-exporter.nix
]
