##! pkgs/system/_systemd-abilities/platform/presets.nix — Systemd preset policy for package targets.
##!
##! RFC-0001 package units ship inert: their files are present, but only the
##! package target is enabled by preset policy. The image contributes the
##! default-deny preset file, while host-specific and runtime `apm` layers add
##! earlier `enable aos-pkg-<name>.target` rules.
{
  abilitySelection ? null,
  config,
  lib,
  ...
}: let
  managerBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "system-manager";
  selected = builtins.length managerBindings == 1;
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

  config.system.build.systemdPresetText = lib.mkIf selected imagePresetText;

  options.system.build.systemdPresetText = lib.mkOption {
    type = lib.types.lines;
    readOnly = true;
    internal = true;
    description = "Pure package-owned systemd preset plan.";
  };
}
