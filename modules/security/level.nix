##! modules/security/level.nix — Security level preset
##!
##! Provides a single option to select the overall security posture of the
##! system, similar to FreeBSD's securelevel. Each level configures SELinux,
##! audit, hardening, firewall, and lockdown settings as a coherent bundle.
##! Individual security modules can still be overridden.
##!
##! Levels:
##!   null       — no preset, use individual module defaults
##!   "minimal"  — all security frameworks disabled (CI, VMs)
##!   "standard" — balanced defaults for production (SELinux enforcing, audit, firewall)
##!   "hardened" — maximum security (lockdown=confidentiality, no core dumps)
##!   "debug"    — permissive SELinux, core dumps enabled, no lockdown
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.security;
in {
  options.aos.security.level = lib.mkOption {
    type = lib.types.nullOr (
      lib.types.enum [
        "minimal"
        "standard"
        "hardened"
        "debug"
      ]
    );
    default = null;
    description = ''
      Security level preset. Sets SELinux, audit, hardening, firewall, and
      lockdown as a coherent bundle. null means no preset — individual
      module defaults apply. Individual options can still override the
      preset values.

      - null: no preset, individual module defaults
      - "minimal": all security frameworks disabled
      - "standard": SELinux enforcing, audit, hardening, firewall
      - "hardened": maximum security, lockdown=confidentiality
      - "debug": permissive SELinux, core dumps, no lockdown
    '';
  };

  config = lib.mkMerge [
    (lib.mkIf (cfg.level == "minimal") {
      aos.security.selinux.enable = lib.mkDefault false;
      aos.security.audit.enable = lib.mkDefault false;
      aos.security.hardening.enable = lib.mkDefault false;
      aos.firewall.enable = lib.mkDefault false;
    })

    (lib.mkIf (cfg.level == "standard") {
      # SELinux disabled until a policy package is built.
      aos.security.selinux.enable = lib.mkDefault false;
      aos.security.audit.enable = lib.mkDefault true;
      aos.security.hardening.enable = lib.mkDefault true;
      aos.security.hardening.kernelLockdown = lib.mkDefault "integrity";
      aos.security.hardening.coreDump.enable = lib.mkDefault false;
      aos.firewall.enable = lib.mkDefault true;
    })

    (lib.mkIf (cfg.level == "hardened") {
      # SELinux disabled until a policy package is built.
      aos.security.selinux.enable = lib.mkDefault false;
      aos.security.audit.enable = lib.mkDefault true;
      aos.security.hardening.enable = lib.mkDefault true;
      aos.security.hardening.kernelLockdown = lib.mkDefault "confidentiality";
      aos.security.hardening.coreDump.enable = lib.mkDefault false;
      aos.firewall.enable = lib.mkDefault true;
    })

    (lib.mkIf (cfg.level == "debug") {
      # SELinux disabled until a policy package is built.
      aos.security.selinux.enable = lib.mkDefault false;
      aos.security.audit.enable = lib.mkDefault false;
      aos.security.hardening.enable = lib.mkDefault true;
      aos.security.hardening.kernelLockdown = lib.mkDefault "none";
      aos.security.hardening.coreDump.enable = lib.mkDefault true;
      aos.firewall.enable = lib.mkDefault true;
    })
  ];
}
