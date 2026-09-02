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
    aos.boot.initrd.extraPackages = [pkgs.aos.packageRuntime pkgs.erofs-utils];

    boot.initrd.systemd.services."aos-credential-recovery" = {
      description = "Recover interrupted AOS credential publication";
      requiredBy = ["initrd-fs.target"];
      before = [
        "aos-config-seed.service"
        "etc-overlay-setup.service"
        "initrd-switch-root.target"
      ];
      requires = ["mount-var.service"];
      after = ["mount-var.service"];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        AOS_ROOT=/sysroot ${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped recover-credential-transactions
      '';
    };

    boot.initrd.systemd.services."aos-config-seed" = {
      description = "Seed the per-generation /etc lower for on-host configuration";
      wantedBy = ["initrd-fs.target"];
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
        # AOS_PROFILE_GEN is published by aos-seed-profiles.service.
        EnvironmentFile = "/run/aos-profile-gen.env";
      };
      script = ''
        set -euo pipefail
        lower="/run/etc/config-$AOS_PROFILE_GEN/etc"
        generation="/sysroot/var/lib/profiles/system/gen-$AOS_PROFILE_GEN"
        manifest="$generation/manifest.json"
        ${pkgs.coreutils}/bin/mkdir -p "$lower"
        if [ -s "$manifest" ]; then
          ${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped __materialize \
            --manifest "$manifest" \
            --generation-dir "$generation" \
            --mkfs-erofs ${pkgs.erofs-utils}/bin/mkfs.erofs \
            --fsck-erofs ${pkgs.erofs-utils}/bin/fsck.erofs
          ${pkgs.util-linux}/bin/mount -t erofs -o ro,nodev,nosuid \
            "$generation/config-lower/etc.erofs" "$lower"
        fi
      '';
    };
  };
}
