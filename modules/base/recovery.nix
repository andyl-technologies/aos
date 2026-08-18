##! Signed recovery environment
##!
##! Builds the dedicated recovery initrd used by RFC-0013 recovery UKIs. The
##! recovery archive has its own static unit graph; it does not inherit the
##! normal initrd and then attempt to mask normal root, provisioning, TPM
##! unlock, networking, or switch-root services.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.boot.recovery;
in {
  options.aos.boot.recovery = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = config.aos.boot.secureBoot.enable && config.aos.security.verity.enable;
      defaultText = "aos.boot.secureBoot.enable && aos.security.verity.enable";
      description = ''
        Build paired, signed recovery UKIs with a dedicated initrd. Enabled by
        default for Secure Boot images with authenticated immutable roots.
      '';
    };

    abi = lib.mkOption {
      type = lib.types.enum [1];
      default = 1;
      description = "Recovery interface and artifact compatibility ABI (currently version 1).";
    };
  };

  options.system.build.recoveryInitrd = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = ''
      Dedicated initrd used only by signed recovery UKIs. It contains no
      normal-root mount, switch-root, provisioning, TPM unlock, or network
      activation path.
    '';
  };

  options.system.build.recoverySlotManifest = lib.mkOption {
    type = lib.types.nullOr lib.types.package;
    default = null;
    description = ''
      db-authenticated immutable-slot metadata embedded in the paired recovery
      UKIs and consumed by the offline verifier.
    '';
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.aos.boot.secureBoot.enable;
        message = "aos.boot.recovery.enable requires Secure Boot signing.";
      }
      {
        assertion = config.aos.security.verity.enable;
        message = "aos.boot.recovery.enable requires dm-verity root images.";
      }
    ];
  };
}
