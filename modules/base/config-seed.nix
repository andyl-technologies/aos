##! modules/base/config-seed.nix — on-host configuration files backend
##!
##! The initrd files backend for on-host configuration. The neutral `/etc` overlay
##! (`etc-overlay-setup.service`, in modules/services/boot-substrate.nix)
##! composes a per-generation lower at `/run/etc/config-<gen>/etc`; first-boot
##! `/etc` comes entirely from the baked system EROFS (gen-0) — the per-gen
##! lower is *empty* — and subsequent config generations are rendered by the
##! stage-2 `aos-eval` fixpoint and switched in by `activate`, post-pivot. So
##! all this initrd unit must do is create the empty lower the overlay expects.
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
        "aos-seed-profiles.service"
        "run-etc-setup.service"
      ];
      after = [
        "mount-var.service"
        "aos-seed-profiles.service"
        "run-etc-setup.service"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # AOS_PROFILE_GEN is published by aos-seed-profiles.service.
        EnvironmentFile = "/run/aos-profile-gen.env";
        # The lower is intentionally empty on first boot.
        ExecStart =
          "${pkgs.coreutils}/bin/mkdir -p "
          + "/run/etc/config-\${AOS_PROFILE_GEN}/etc";
      };
    };
  };
}
