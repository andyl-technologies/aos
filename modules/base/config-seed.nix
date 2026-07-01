##! modules/base/config-seed.nix — new-path files backend (RFC-0011)
##!
##! When Ignition is disabled (`aos.provisioning.ignition.enable = false`) the
##! on-host config-eval path replaces `ignition-files` as the initrd "files"
##! backend. The neutral `/etc` overlay (`etc-overlay-setup.service`, in
##! modules/services/ignition.nix) composes a per-generation lower at
##! `/run/etc/ignition-<gen>/etc`; on the Ignition path that subtree was created
##! and populated by `ignition-files`. On the new path the first-boot `/etc`
##! comes entirely from the baked system EROFS (gen-0) — the per-gen lower is
##! *empty* — and subsequent config generations are rendered by the stage-2
##! `aos-eval` fixpoint and switched in by `activate`, post-pivot. So all this
##! initrd unit must do is create the empty lower the overlay expects.
##!
##! Emitted exactly when Ignition is off, so it is the `filesUnit` the
##! provisioning-backend indirection resolves to in that mode. Inert (and absent)
##! on every existing Ignition system, so they evaluate unchanged.
{
  config,
  pkgs,
  lib,
  ...
}: {
  config = {
    boot.initrd.systemd.services."aos-config-seed" = {
      description = "Seed the per-generation /etc lower for on-host config (RFC-0011)";
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
        # The Ignition path had ignition-files' ExecStartPre create this; on the
        # new path the lower is intentionally empty on first boot.
        ExecStart =
          "${pkgs.coreutils}/bin/mkdir -p "
          + "/run/etc/ignition-\${AOS_PROFILE_GEN}/etc";
      };
    };
  };
}
