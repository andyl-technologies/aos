##! Package-owned security level policy — Security level preset
##!
##! Provides a single option to select the overall security posture of the
##! system, similar to FreeBSD's securelevel. Each level configures SELinux,
##! audit, hardening, and firewall settings as a coherent bundle.
##! Individual security modules can still be overridden.
##!
##! Levels:
##!   null       — no preset, use individual module defaults
##!   "minimal"  — all security frameworks disabled (CI, VMs)
##!   "standard" — balanced defaults for production (SELinux enforcing, audit, firewall)
##!   "hardened" — maximum security (no core dumps)
##!   "debug"    — permissive SELinux, core dumps enabled
{
  config,
  options,
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
      Security level preset. Sets SELinux, audit, hardening, and firewall
      as a coherent bundle. null means no preset — individual module
      defaults apply. Individual options can still override the preset
      values.

      - null: no preset, individual module defaults
      - "minimal": all security frameworks disabled
      - "standard": SELinux enforcing, audit, hardening, firewall
      - "hardened": maximum security
      - "debug": permissive SELinux, core dumps
    '';
  };

  config = lib.mkIf (cfg.level != null && (config.aos.boot.stage or "host") == "host") (lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.level == "minimal" || (options.aos ? networkPolicy);
          message = "The selected security preset requires the firewall package module.";
        }
        {
          assertion = builtins.elem cfg.level ["minimal" "debug"] || (options.aos.security ? audit);
          message = "The selected security preset requires the audit package module.";
        }
      ];
      aos.security.hardening = {
        enable = lib.mkDefault (cfg.level != "minimal");
        coreDump.enable = lib.mkDefault (cfg.level == "debug");
      };
    }
    (lib.optionalAttrs (options.aos.security ? selinux) {
      aos.security.selinux.enable = lib.mkDefault false;
    })
    (lib.optionalAttrs (options.aos.security ? audit) {
      aos.security.audit.enable = lib.mkDefault (builtins.elem cfg.level ["standard" "hardened"]);
    })
    (lib.optionalAttrs (options.aos ? networkPolicy) {
      aos.networkPolicy.enable = lib.mkDefault (cfg.level != "minimal");
    })
  ]);
}
