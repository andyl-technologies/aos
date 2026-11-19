##! pkgs/system/_systemd-abilities/platform/presets.nix — Systemd preset policy for package targets.
##!
##! The image ships `/usr/lib/systemd/system-preset` with any rules selected
##! here and a final default-deny `disable *` file. No boot service applies
##! these presets: image units are enabled by stage-2 `.wants` links, and
##! package services by native activation. The files take effect only through
##! an explicit `systemctl preset` or `systemctl preset-all`.
{
  config,
  lib,
  ...
}: let
  imagePresetRules = config.systemd.systemPresetRules;
  imagePresetText =
    lib.optionalString (imagePresetRules != [])
    "${lib.concatStringsSep "\n" imagePresetRules}\n";
in {
  options.systemd.systemPresetRules = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [];
    extensible = true;
    description = "Ordered systemd preset rules selected for this system.";
  };

  config.system.build.systemdPresetText = imagePresetText;

  options.system.build.systemdPresetText = lib.mkOption {
    type = lib.types.lines;
    readOnly = true;
    internal = true;
    description = "Pure package-owned systemd preset plan.";
  };
}
