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
  selected = builtins.length managerBindings == 1;
  selectedBinding =
    if selected
    then builtins.head managerBindings
    else null;
  providerReady =
    selected
    && selectedBinding.implementation.value.provide != null;

  packageOutput = package: lib.abilities.packageOutput {inherit package;};
  managerArtifactNames = [
    "aos-systemd-provider"
    "bash"
    "coreutils"
    "cpio"
    "cryptsetup"
    "e2fsprogs"
    "findutils"
    "gawk"
    "gptfdisk"
    "grep"
    "iproute2"
    "jq"
    "kmod"
    "less"
    "linux-pam"
    "sed"
    "util-linux"
    "zstd"
  ];
  managerArtifactSelectors = builtins.map packageOutput managerArtifactNames;
  managerArtifacts = builtins.listToAttrs (builtins.map
    (name: {
      inherit name;
      value = packageArtifactFor (packageOutput name);
    })
    managerArtifactNames);
  systemdPackage = packageArtifactFor (lib.abilities.packageOutput {});
  providerPackage = managerArtifacts.aos-systemd-provider;
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
      inherit (config.system.build.systemdMaterializationData) etc jobScripts;
    };
    renderPlan = plan:
      runCommand (builtins.unsafeDiscardStringContext plan.name) {
        realization = plan.input;
        passAsFile = ["realization"];
      } ''
        ${providerPackage}/bin/aos-systemd-provider render
      '';
    providerArtifacts = builtins.map renderPlan config.systemd.providerUnitPlans;
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
    managerConfigurations =
      builtins.map renderPlan config.systemd.providerManagerConfigurationPlans;
    networkConfigurations =
      builtins.map renderPlan config.systemd.providerNetworkConfigurationPlans;
  in
    runCommand "systemd-manager-configuration" {} ''
      mkdir -p "$out"
      ln -s ${units} "$out/systemd-units"
      ln -s ${presets} "$out/systemd-presets"
      ${lib.optionalString (managerConfigurations != []) ''
        ln -s ${builtins.head managerConfigurations} "$out/systemd-manager-configuration"
      ''}
      ${lib.optionalString (networkConfigurations != []) ''
        ln -s ${builtins.head networkConfigurations} "$out/systemd-network-configuration"
      ''}
    '';
  buildInitrd = import ./platform/build-initrd.nix {
    inherit config initrdAbilityEvaluation initrdStaticContract lib;
    artifacts = managerArtifacts;
    systemdArtifact = systemdPackage;
  };
  selectedManagerOutput =
    config.aos.abilities.compositionOutputs.${selectedBinding.binding.request}."selected-manager".value or null;
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
      rootfs = {
        closureRoots = [systemdPackage];
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
  managerProjectionReady =
    selectedManagerOutput
    != null
    && selectedManagerOutput == managerArtifact;
  checkedProviderReady =
    providerReady
    && (
      if managerProjectionReady
      then true
      else throw "selected system manager projection differs from its checked planning output"
    );
in {
  config = {
    aos.abilities = {
      implementations.system-manager = {
        description = "Realizes systemd host and initrd manager artifacts.";
        interface = managerInterface.alias;
        artifact = managerArtifact;
        artifacts = managerArtifactSelectors;
        methods = [];
        guarantees = [];
        providerModule = {
          artifact = lib.abilities.packageOutput {output = "module";};
          path = "provider/systemd.nix";
        };
      };
    };

    aos.manager.selected = lib.mkIf checkedProviderReady authoredManager;
  };
}
