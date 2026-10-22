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
  bootstrapServices = import ./bootstrap-services.nix {
    inherit config lib;
    pkgs = managerArtifacts;
  };
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
    bootstrapJSON = builtins.toJSON bootstrapServices;
    bootstrapGroupsJSON = builtins.toJSON (lib.mapAttrsToList (_: group: group.input) (import ./bootstrap-resource-groups.nix {inherit config lib;}));
    units =
      runCommand "systemd-native-bootstrap-units" {
        inherit bootstrapJSON bootstrapGroupsJSON;
        passAsFile = ["bootstrapJSON" "bootstrapGroupsJSON"];
      } ''
        ${pkgs.buildPackages.systemd.handlers}/bin/aos-service-handler render --output-dir "$out" < "$bootstrapJSONPath"
        ${pkgs.buildPackages.systemd.handlers}/bin/aos-systemd-native-resources render-resource-groups --output-dir "$out" < "$bootstrapGroupsJSONPath"
        # Native and typed declarations may contribute distinct drop-ins, but
        # neither may silently replace the other's actual unit or install link.
        ${pkgs.findutils}/bin/find ${baseUnits} -mindepth 1 \( -type f -o -type l \) -print | while IFS= read -r source; do
          destination="$out/''${source#${baseUnits}/}"
          if [ -e "$destination" ] || [ -L "$destination" ]; then
            echo "Native and typed manager entries collide: $destination" >&2
            exit 1
          fi
        done
        # Keep the new output writable for its own metadata finalization.
        cp -a --no-preserve=mode ${baseUnits}/. "$out/"

        # Explicit requests retain unchanged selected-package bases beside
        # authored drop-ins. Ordinary images request none; every collision fails.
        ${lib.concatMapStringsSep "\n" (name: ''
            if [ -e "$out/${name}" ] || [ -L "$out/${name}" ]; then
              echo "The requested package base collides with another manager entry: ${name}" >&2
              exit 1
            fi
            cp --no-preserve=mode ${systemdPackage}/lib/systemd/system/${name} "$out/${name}"
          '')
          config.systemd.packagedBaseUnits}
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
      mkdir -p "$out/systemd-vendor-units"
      ln -s ${units} "$out/systemd-units"
      ln -s ${presets} "$out/systemd-presets"

      # PID 1 already searches this exact package's vendor directory. Publish
      # its unchanged inodes under the conventional policy paths as well, so
      # image labeling assigns unit types instead of generic store-data types.
      for unit in ${systemdPackage}/lib/systemd/system/*; do
        ln -s "$unit" "$out/systemd-vendor-units/$(basename "$unit")"
      done
    '';
  buildInitrd = import ./platform/build-initrd.nix {
    inherit config initrdAbilityEvaluation lib;
    artifacts = managerArtifacts;
    systemdArtifact = systemdPackage;
  };
  authoredManager = {
    _type = "aos-selected-manager";
    name = "systemd";
    package = toString systemdPackage;
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
        # Bootstrapping reads the declaration; the live installer prepares the
        # identical command for subsequent launches without replacing PID 1.
        initExecutable = config.aos.abilities.initSystem.operations.install.effects.default.input.executable;
        trees = [
          {
            collision = "reject";
            destination = "/usr/lib/systemd/system";
            source = "systemd-vendor-units";
          }
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

  options.system.build = {
    systemdBootstrapServices = lib.mkOption {
      type = lib.types.attrsOf lib.types.attrs;
      readOnly = true;
      internal = true;
      description = "Exact enabled service inputs consumed by the native bootstrap renderer.";
    };
    systemdBootstrapServiceOwners = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      readOnly = true;
      internal = true;
      description = "Authenticated effect owner of each native bootstrap service input.";
    };
    systemdPackagedUnitOwners = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      readOnly = true;
      internal = true;
      description = "Selected package output supplying each unchanged manager base unit.";
    };
  };

  config = {
    aos.manager.selected = authoredManager;
    system.build = {
      systemdBootstrapServices = bootstrapServices;
      systemdBootstrapServiceOwners =
        builtins.mapAttrs
        (name: _: config.aos.abilities.serviceManagement.operations.realize.effects.${name}.contract.owner)
        bootstrapServices;
      systemdPackagedUnitOwners = lib.genAttrs config.systemd.packagedBaseUnits (_: toString systemdPackage);
    };
  };
}
