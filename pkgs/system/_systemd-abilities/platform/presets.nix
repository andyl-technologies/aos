##! pkgs/system/_systemd-abilities/platform/presets.nix — Systemd preset policy for package targets.
##!
##! Package targets (`aos-pkg-<name>.target`) ship inert: their unit files are
##! present, but only preset policy enables them. The image contributes the
##! default-deny preset file, while host-specific and runtime `apm` layers add
##! earlier `enable aos-pkg-<name>.target` rules.
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
