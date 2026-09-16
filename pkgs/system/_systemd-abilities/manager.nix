##! Systemd manager implementation selected through the checked ability graph.
{
  abilitySelection ? null,
  config,
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
    && (builtins.head managerBindings).request == "system:manager";

  buildManagerConfiguration = {runCommand}:
    runCommand "systemd-manager-configuration" {} ''
      mkdir -p "$out"
      ln -s ${config.system.build.systemdSystemUnits} "$out/systemd-units"
      ln -s ${config.system.build.systemdSystemPresets} "$out/systemd-presets"
    '';
  manager = {
    _type = "aos-selected-manager";
    name = "systemd";
    package = packageArtifactFor managerArtifact;
    configuration = {
      buildOutput = buildManagerConfiguration;
      executableScripts = config.system.build.systemdJobScripts;
      filesystemEntries = config.system.build.systemdEtcEntries;
      ownership = {
        executableScripts = config.system.build.systemdJobScriptOwners;
        filesystemEntries = config.system.build.systemdEtcEntryOwners;
      };
    };
  };
in {
  config = {
    aos.abilities = {
      implementations.system-manager = {
        description = "Realizes systemd host and initrd manager artifacts.";
        interface = managerInterface.alias;
        artifact = managerArtifact;
        methods = [];
        guarantees = [];
      };
    };

    aos.manager.selected = lib.mkIf selected manager;
  };
}
