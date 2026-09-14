##! System-owned service documentation inventory.
##!
##! Package configuration companions document package-owned services directly.
##! This module records the smaller set of services whose options and units are
##! implemented by the host module graph, so documentation derives from the
##! same evaluated system that owns those declarations.
{lib, ...}: {
  options.aos.documentation.systemServices = lib.mkOption {
    internal = true;
    default = {};
    description = "System-owned package documentation projections.";
    type = lib.types.attrsOf (lib.types.submodule {
      options = {
        optionPrefixes = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          description = "Public option prefixes owned by the service package.";
        };

        units = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          description = "System units implemented for the service package.";
        };
      };
    });
  };

  config.aos.documentation.systemServices = {
    aos = {
      optionPrefixes = ["aos"];
      units = [
        "aos-attest.service"
        "aos-eval.service"
        "aos-firstboot-reeval.service"
        "aos-host-config-cache.service"
        "aos-host-config-restore.service"
        "aos-image-boot-commit.service"
        "aos-install-baked-packages.service"
        "aos-nix-db.service"
        "aos-provisioning-persist.service"
        "aos-registry-sync.service"
      ];
    };

    aos-hub = {
      optionPrefixes = ["aos.registry-hub"];
      units = ["aos-hub.service"];
    };

    audit = {
      optionPrefixes = ["aos.security.audit"];
      units = ["audit-rules.service" "auditd.service"];
    };

    chrony = {
      optionPrefixes = ["aos.services.chrony"];
      units = ["chronyd.service"];
    };

    dbus = {
      optionPrefixes = ["aos.services.dbus"];
      units = ["dbus.service" "dbus.socket"];
    };

    nftables = {
      optionPrefixes = ["aos.firewall"];
      units = ["nftables.service"];
    };

    openssh = {
      optionPrefixes = ["aos.services.ssh"];
      units = ["aos-ssh-ready.service" "sshd-keygen.service" "sshd.service"];
    };

    smartmontools = {
      optionPrefixes = ["aos.monitoring.hardware"];
      units = ["smartd.service"];
    };

    systemd = {
      optionPrefixes = ["aos.networking" "boot.initrd.systemd" "systemd"];
      units = ["systemd-networkd.service" "systemd-resolved.service"];
    };
  };
}
