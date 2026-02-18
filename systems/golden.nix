# systems/golden.nix — Golden image system variant
#
# A single unified image that uses cloud-init to activate services at runtime
# based on JSON userdata. Replaces per-role system variants (server,
# k8s-worker, k8s-control-plane) with one image that can serve any role.
#
# Always enabled:
#   - Security hardening (SELinux, audit, hardening, firewall, SSH, fail2ban)
#   - NTP time sync (chrony)
#   - Cloud-init (JSON userdata processor)
#
# Activated at boot by cloud-init based on userdata role:
#   - Server: nftables rules for server ports
#   - K8s worker: containerd config, k3s agent config, kernel prereqs
#   - K8s control plane: worker config + API server/etcd ports, k3s server config
{
  config,
  pkgs,
  lib,
  ...
}: {
  imports = [
    ./base.nix
    ../modules/security/selinux.nix
    ../modules/security/audit.nix
    ../modules/security/hardening.nix
    ../modules/security/firewall.nix
    ../modules/security/ssh.nix
    ../modules/security/fail2ban.nix
    ../modules/services/chrony.nix
    ../modules/services/cloud-init.nix
  ];

  aos.system.variant = "golden";

  # --- Security (always on) ---
  aos.security.selinux.enable = true;
  aos.security.selinux.mode = "enforcing";
  aos.security.audit.enable = true;
  aos.security.hardening.enable = true;

  # --- Firewall (always on, cloud-init overrides rules at boot) ---
  aos.firewall.enable = true;

  # --- Services (always on) ---
  aos.services.ssh.enable = true;
  aos.services.chrony.enable = true;
  aos.services.cloudInit.enable = true;
}
