##! Records image-owned native leaves without freezing package policy values.
{
  lib,
  pkgs,
  configurationLower ? pkgs.aos-configuration-lower,
}: {
  packages,
  configuration,
  scope,
  ...
}: let
  initial = lib.evalPackageModules {
    inherit packages scope;
    operatorModules = configuration;
  };
  effects = initial.config.aos.abilities.configuration.operations.file.effects;
  managedPaths = lib.sort builtins.lessThan (lib.unique (
    builtins.attrNames initial.config.aos.configurationLower.files
    ++ lib.mapAttrsToList (_: effect: lib.removePrefix "/etc/" effect.input.path)
    (lib.filterAttrs (_: effect:
      effect.enable
      && builtins.isString effect.input.path
      && lib.hasPrefix "/etc/" effect.input.path)
    effects)
  ));
  trees = initial.config.aos.filesystems.etcTrees;
  inventory = pkgs.mkDerivation {
    pname = "aos-image-configuration-inventory";
    version = "1";
    module = ./image-inventory;
    moduleDeps = [configurationLower];
    src = null;
    buildDeps = [pkgs.buildPackages.python3];
    runtimeDeps = [];
    passthru.nativeManagedPaths = managedPaths;
    inputsJSON = builtins.toJSON {
      files = managedPaths;
      inherit trees;
    };
    passAsFile = ["inputsJSON"];
    phases = [
      {
        name = "record-managed-paths";
        script = ''
          mkdir -p "$out"
          ${pkgs.buildPackages.python3}/bin/python3 ${./managed-paths.py} "$inputsJSONPath" "$out/managed-paths.json"
        '';
      }
    ];
  };
in
  # The checked-in module receives its immutable inventory through the native
  # artifact argument. Neither stage evaluation nor replay reads built outputs.
  {
    packages = [inventory];
    configuration = [];
  }
