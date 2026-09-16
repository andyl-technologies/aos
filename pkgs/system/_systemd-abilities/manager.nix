##! Systemd manager implementation selected through the checked ability graph.
{
  abilitySelection ? null,
  config,
  initrdAbilityEvaluation ? null,
  initrdStaticContract ? null,
  lib,
  packageArtifactFor,
  ...
}: let
  managerInterface = lib.abilities.interfaces.systemManager.interfaces.manager;
  managerArtifact = lib.abilities.packageOutput {};
  managerBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation "system-manager";
  selected =
    builtins.length managerBindings == 1
    && (builtins.head managerBindings).binding.request == "system:manager";

  packageOutput = package: lib.abilities.packageOutput {inherit package;};
  systemdPackage = packageArtifactFor (lib.abilities.packageOutput {});
  providerPackage = packageArtifactFor (packageOutput "aos-systemd-provider");
  rendererPackages = buildContext: {
    inherit (buildContext) runCommand writeTextFile;
    bash = packageArtifactFor (packageOutput "bash");
    coreutils = packageArtifactFor (packageOutput "coreutils");
    findutils = packageArtifactFor (packageOutput "findutils");
    grep = packageArtifactFor (packageOutput "grep");
    sed = packageArtifactFor (packageOutput "sed");
    systemd = systemdPackage;
  };

  buildManagerConfiguration = buildContext: let
    inherit (buildContext) runCommand;
    systemdLib = import ./platform/render.nix {
      inherit lib;
      pkgs = rendererPackages buildContext;
    };
    baseUnits = systemdLib.materializeUnits {
      type = "system";
      inherit (config.system.build.systemdMaterializationData) etc jobScripts;
    };
    providerArtifacts = config.systemd.providerUnitArtifacts;
    providerArtifactsJson = builtins.toJSON providerArtifacts;
    units =
      if providerArtifacts == []
      then baseUnits
      else
        runCommand "systemd-system-units-with-provider-artifacts" {
          inherit baseUnits providerArtifactsJson;
          passAsFile = ["providerArtifactsJson"];
        } ''
          providerArtifactsPath="$providerArtifactsJsonPath" \
            ${providerPackage}/bin/aos-systemd-provider assemble
        '';
    presets = runCommand "systemd-system-preset" {
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
    inherit config initrdAbilityEvaluation initrdStaticContract lib packageArtifactFor;
  };
  selectedManagerOutput =
    config.aos.abilities.compositionOutputs."system:manager"."selected-manager".value or null;
  authoredManager = {
    _type = "aos-selected-manager";
    name = "systemd";
    package = systemdPackage;
    configuration = {
      inherit buildInitrd;
      buildOutput = buildManagerConfiguration;
      executableScripts = config.system.build.systemdJobScripts;
      filesystemEntries = config.system.build.systemdEtcEntries;
      ownership = {
        executableScripts = config.system.build.systemdJobScriptOwners;
        filesystemEntries = config.system.build.systemdEtcEntryOwners;
      };
    };
  };
  manager =
    if
      selectedManagerOutput != null
      && selectedManagerOutput._type == "aos-artifact-reference"
      && selectedManagerOutput.store_path == builtins.toString systemdPackage
    then authoredManager
    else throw "selected system manager projection differs from its checked planning output";
in {
  imports = lib.optionals selected [
    ./platform/system.nix
    ./platform/initrd.nix
    ./platform/presets.nix
  ];

  config = {
    aos.abilities = {
      implementations.system-manager = {
        description = "Realizes systemd host and initrd manager artifacts.";
        interface = managerInterface.alias;
        artifact = managerArtifact;
        methods = [];
        guarantees = [];
        providerModule = {
          artifact = managerArtifact;
          path = "share/aos/providers/systemd.nix";
        };
      };
    };

    aos.manager.selected = lib.mkIf selected manager;
  };
}
