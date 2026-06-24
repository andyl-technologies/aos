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

    systemd.services.aos-preset = {
      description = "Apply AOS package preset policy";
      wantedBy = ["multi-user.target"];
      before = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        ${pkgs.systemd}/bin/systemctl preset-all --preset-mode=enable-only

        targets="$(
          ${pkgs.systemd}/bin/systemctl list-unit-files 'aos-pkg-*.target' \
            --type=target \
            --state=enabled \
            --no-legend \
            --no-pager 2>/dev/null \
            | while read -r unit _rest; do
                [ -n "$unit" ] && printf '%s\n' "$unit"
              done
        )"

        if [ -n "$targets" ]; then
          ${pkgs.systemd}/bin/systemctl start --no-block $targets
        fi
      '';
    };
  };
}
