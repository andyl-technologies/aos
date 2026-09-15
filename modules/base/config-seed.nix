##! modules/base/config-seed.nix — on-host configuration files backend
##!
##! The initrd files backend for on-host configuration. The neutral `/etc` overlay
##! (`etc-overlay-setup.service`, in modules/services/boot-substrate.nix)
##! composes a per-generation lower at `/run/etc/config-<gen>/etc`. On reboot
##! this unit validates and mounts the committed generation's retained EROFS
##! artifact before the overlay is mounted. The materializer emits only
##! host/package-owned deltas; image-owned `@base` files come from the immutable
##! running image lower.
##! Gen-0 (or a legacy generation with no manifest) remains an empty fallback.
##!
##! Always emitted: it is the `filesUnit` the boot-substrate indirection
##! resolves to.
{
  config,
  pkgs,
  lib,
  ...
}: {
  config = {
    # Keep the materializer's complete runtime closure in stage 1 explicitly.
    # Rendered unit scripts are also part of the initrd closure graph, but this
    # declaration makes the backend self-contained if unit materialization is
    # refactored independently of the initrd package set.
    aos.boot.initrd.extraPackages = [pkgs.aos-boot-preparations];

    boot.initrd.systemd.services."aos-credential-recovery" = {
      description = "Recover interrupted AOS credential publication";
      requiredBy = ["initrd-fs.target"];
      before = [
        "aos-config-seed.service"
        "etc-overlay-setup.service"
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
      # Immutable identity and every runtime dependency resolve through the
      # target root's /nix overlay. Merely waiting for /var leaves recovery
      # racing nix-overlay-setup on first boot. Recovery also reads the mounted
      # target root itself, so keep sysroot as an explicit ordering dependency.
      requires = [
        "sysroot.mount"
        "mount-var.service"
        "nix-overlay-setup.service"
      ];
      after = [
        "sysroot.mount"
        "mount-var.service"
        "nix-overlay-setup.service"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        ${pkgs.aos-boot-preparations}/bin/aos-boot-preparations recover-credentials
      '';
    };

    boot.initrd.systemd.services."aos-config-seed" = {
      description = "Seed the per-generation /etc lower for on-host configuration";
      requiredBy = ["initrd-fs.target"];
      before = [
        "etc-overlay-setup.service"
        "initrd-switch-root.target"
        "initrd-fs.target"
      ];
      requires = [
        "mount-var.service"
        "aos-credential-recovery.service"
        "aos-seed-profiles.service"
        "run-etc-setup.service"
      ];
      after = [
        "mount-var.service"
        "aos-credential-recovery.service"
        "aos-seed-profiles.service"
        "run-etc-setup.service"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        ${pkgs.aos-boot-preparations}/bin/aos-boot-preparations seed-configuration
      '';
    };
  };
}
