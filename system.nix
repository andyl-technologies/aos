# system.nix — AOS system definition
#
# A single unified image that uses cloud-init to activate services at runtime
# based on JSON userdata. Like Debian, there is one image that adapts to its
# role at boot time.
#
# Always enabled:
#   - System identity (os-release, hostname, locale, timezone)
#   - systemd-boot with kernel and initrd
#   - Root and ESP filesystem layout
#   - Basic networking (systemd-networkd, resolved)
#   - Core user accounts (root + aos service user)
#   - Ignition for first-boot machine provisioning
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
    # Base system
    ./modules/base/build.nix
    ./modules/base/system.nix
    ./modules/base/boot.nix
    ./modules/base/filesystems.nix
    ./modules/base/networking.nix
    ./modules/base/users.nix
    ./modules/base/journald.nix
    ./modules/base/kernel.nix
    ./modules/base/swap.nix
    ./modules/services/ignition.nix
    ./modules/image/default.nix

    # Security
    ./modules/security/selinux.nix
    ./modules/security/audit.nix
    ./modules/security/hardening.nix
    ./modules/security/firewall.nix
    ./modules/security/ssh.nix
    ./modules/security/fail2ban.nix
    ./modules/security/opkssh.nix

    # Services
    ./modules/services/chrony.nix
    ./modules/services/cloud-init.nix
  ];

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
