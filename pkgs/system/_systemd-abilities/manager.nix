##! Systemd manager implementation selected through the checked ability graph.
{
  config,
  initrdAbilityEvaluation ? null,
  lib,
  pkgs,
  ...
}: let
  managerArtifacts = pkgs;
  systemdPackage = pkgs.systemd;
  bootstrapConfiguration = import ./bootstrap-config.nix {inherit config lib;};
  rendererPackages = buildContext: {
    inherit (buildContext) runCommand writeTextFile;
    inherit (managerArtifacts) bash coreutils findutils grep sed;
    systemd = systemdPackage;
  };

  buildManagerConfiguration = buildContext: let
    inherit (buildContext) runCommand;
    renderer = rendererPackages buildContext;
    systemdLib = import ./platform/render.nix {
      inherit lib;
      pkgs = renderer;
    };
    baseUnits = systemdLib.materializeUnits {
      type = "system";
      etc = config.system.build.systemdEtcEntries;
      jobScripts = config.system.build.systemdJobScripts;
    };
    bootstrapServices = import ./bootstrap-services.nix {
      inherit config lib;
      pkgs = managerArtifacts;
    };
    bootstrapJSON = builtins.toJSON bootstrapServices;
    units =
      runCommand "systemd-native-bootstrap-units" {
        inherit bootstrapJSON;
        passAsFile = ["bootstrapJSON"];
      } ''
        ${pkgs.buildPackages.systemd}/bin/aos-service-handler render --output-dir "$out" < "$bootstrapJSONPath"
        # Keep the new output writable for its own metadata finalization.
        cp -a --no-preserve=mode ${baseUnits}/. "$out/"
      '';
    presets =
      runCommand "systemd-system-preset" {
        presetRules = config.system.build.systemdPresetText;
        passAsFile = ["presetRules"];
      } ''
        mkdir -p "$out"
        if [ -s "$presetRulesPath" ]; then
          cp "$presetRulesPath" "$out/50-aos-image-packages.preset"
        fi
        printf 'disable *\n' > "$out/99-aos-default.preset"
      '';
  in
    runCommand "systemd-manager-configuration" {} ''
      mkdir -p "$out"
      ln -s ${units} "$out/systemd-units"
      ln -s ${presets} "$out/systemd-presets"
    '';
  buildInitrd = import ./platform/build-initrd.nix {
    inherit config initrdAbilityEvaluation lib;
    artifacts = managerArtifacts;
    systemdArtifact = systemdPackage;
  };
  authoredManager = {
    _type = "aos-selected-manager";
    name = "systemd";
    package = systemdPackage;
    configuration = {
      inherit buildInitrd;
      buildOutput = buildManagerConfiguration;
      executableScripts = config.system.build.systemdJobScripts;
      filesystemEntries = bootstrapConfiguration.filesystemEntries;
      ownership = {
        executableScripts = config.system.build.systemdJobScriptOwners;
        filesystemEntries = bootstrapConfiguration.ownership.filesystemEntries;
      };
      rootfs = {
        closureRoots = ["${systemdPackage}"];
        initExecutable = "${systemdPackage}/lib/systemd/systemd";
        trees = [
          {
            collision = "reject";
            destination = "/usr/lib/systemd/system-preset";
            source = "systemd-presets";
          }
        ];
      };
    };
  };
in {
  imports = [./platform/account-seed.nix];

  config.aos.manager.selected = authoredManager;
}
