##! Loads the retained journal-policy declarations during image selection.
{
  lib,
  pkgs,
  packageModulesAvailable ? false,
  ...
}: {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/system/_aos-host-policy/journald.nix];

  # The real-root machine ID differs from the initrd's. Create its runtime
  # directory before journald installs the no-set-ID guard on the SGID root.
  # Manager units enter the immutable bootstrap unit tree, before activation
  # could materialize ordinary configuration file effects.
  systemd.services.aos-journald-runtime-prep = {
    description = "Prepare the current machine's runtime journal directory";
    before = ["systemd-journald.service"];
    unitConfig.DefaultDependencies = "no";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = ''${pkgs.systemd}/bin/systemd-tmpfiles --create --inline "d /run/log/journal 2755 root systemd-journal -" "d /run/log/journal/%%m 2750 root systemd-journal -"'';
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ReadWritePaths = ["/run"];
    };
  };

  systemd.services.systemd-journald = {
    overrideStrategy = "asDropin";
    requires = ["aos-journald-runtime-prep.service"];
    after = ["aos-journald-runtime-prep.service"];
  };
}
