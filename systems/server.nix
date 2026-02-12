# systems/server.nix — Production server variant
#
# Extends the base system with security hardening, SSH access, automatic
# updates, and time synchronization. Intended for bare-metal and VM servers
# that do not run Kubernetes workloads directly.
#
# Adds over base:
#   - SELinux in enforcing mode
#   - Audit logging (auditd)
#   - Kernel and userspace hardening (sysctl, ASLR, dmesg restriction)
#   - nftables firewall (default-deny inbound)
#   - OpenSSH server (key-only, no root password login)
#   - Automatic OS updates (aos-update.timer)
#   - Nix store garbage collection (aos-gc.timer)
#   - Chrony NTP time synchronization

{ config, pkgs, lib, ... }:

{
  imports = [
    ./base.nix
    ../modules/security/selinux.nix
    ../modules/security/audit.nix
    ../modules/security/hardening.nix
    ../modules/security/firewall.nix
    ../modules/security/ssh.nix
    ../modules/services/update.nix
    ../modules/services/gc.nix
    ../modules/services/chrony.nix
  ];

  aos.system.variant = "server";

  # --- Security ---
  aos.security.selinux.enable = true;
  aos.security.selinux.mode = "enforcing";
  aos.security.audit.enable = true;
  aos.security.hardening.enable = true;

  # --- Firewall ---
  # Default-deny inbound; allow only SSH.
  aos.firewall.enable = true;

  # --- Services ---
  aos.services.ssh.enable = true;
  aos.services.chrony.enable = true;

  # --- Maintenance ---
  aos.update.enable = true;
  aos.gc.enable = true;
}
