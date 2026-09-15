##! modules/systemd/presets.nix — Systemd preset policy for package targets.
##!
##! RFC-0001 package units ship inert: their files are present, but only the
##! package target is enabled by preset policy. The image contributes the
##! default-deny preset file, while host-specific and runtime `apm` layers add
##! earlier `enable aos-pkg-<name>.target` rules.
{
  config,
  lib,
  pkgs,
  ...
}: let
  imagePresetRules = config.systemd.systemPresetRules;
  imagePresetText =
    lib.optionalString (imagePresetRules != [])
    "${lib.concatStringsSep "\n" imagePresetRules}\n";
in {
  options.system.build.systemdSystemPresets = lib.mkOption {
    type = lib.types.package;
    description = ''
      Directory staged into `/usr/lib/systemd/system-preset` on the rootfs.
      It carries image-baked systemd preset policy.
    '';
  };

  config = {
    system.build.systemdSystemPresets =
      pkgs.runCommand "systemd-system-preset" {
        presetRules = imagePresetText;
        passAsFile = ["presetRules"];
      } ''
        mkdir -p "$out"
        ${lib.optionalString (imagePresetRules != []) ''
          cp "$presetRulesPath" "$out/50-aos-image-packages.preset"
        ''}
        printf 'disable *\n' > "$out/99-aos-default.preset"
      '';

  };
}
