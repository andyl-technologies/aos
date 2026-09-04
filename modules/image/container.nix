##! modules/image/container.nix — Per-system OCI artifact projection
##!
##! Associates publishable OCI artifacts with the same evaluated system variant
##! that produces disk images. The OCI builder consumes an explicit userland
##! projection; it never packages the bootable system toplevel, kernel, initrd,
##! bootloader, or other disk-only state.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.containers;
  containerSchema = import ../../lib/containers/schema.nix;
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (pkgs) mkDerivation coreutils findutils gzip jq tar;
  };
  retainedSource = name: source:
    pkgs.writeTextFile {
      name = "aos-container-source-${name}";
      text = builtins.readFile source;
      destination = "/source/${builtins.baseNameOf source}";
    };
  evidenceOverrides = let
    artifacts = config.aos.config.artifacts;
    version = config.aos.system.version;
    bootStorageSource = retainedSource "boot-storage" ../base/boot-storage.nix;
  in [
    {
      output = artifacts.esp-mount;
      outputName = "out";
      pname = "aos-mount-esp";
      inherit version;
      licenses = ["Apache-2.0"];
      sources = [bootStorageSource (retainedSource "mount-esp" ../base/mount-esp.sh.in)];
    }
    {
      output = artifacts.esp-sync;
      outputName = "out";
      pname = "aos-sync-esps";
      inherit version;
      licenses = ["Apache-2.0"];
      sources = [bootStorageSource (retainedSource "sync-esps" ../base/sync-esps.sh.in)];
    }
  ];
  defaultAosDefinition =
    (import ../../containers/aos.nix {
      inherit lib pkgs evidenceOverrides;
      goldenRoots = config.environment.systemPackages;
      aosSystem = pkgs.stdenv.hostPlatform.system;
    }).config;
  systemIdentity = {
    inherit
      (config.aos.system)
      name
      version
      stateVersion
      moduleAbi
      ;
    release = {
      inherit
        (config.aos.release)
        enabled
        tier
        registry
        channel
        rootEpoch
        ;
    };
  };
  definitionAssertions = definition:
    definition.assertions
    ++ [
      {
        assertion = definition.platform.aosSystem == pkgs.stdenv.hostPlatform.system;
        message = "container platform.aosSystem must match the evaluated package-set target";
      }
      {
        assertion =
          definition.platform.architecture
          == (
            if pkgs.stdenv.hostPlatform.system == "x86_64-linux"
            then "amd64"
            else "arm64"
          );
        message = "container OCI architecture must match the evaluated AOS target";
      }
    ];
  checkedDefinition = name: definition: let
    failures = builtins.filter (assertion: !assertion.assertion) (definitionAssertions definition);
    checked =
      if failures == []
      then definition
      else
        throw ''
          Container '${name}' failed evaluation:
          ${lib.concatStringsSep "\n" (map (failure: "  - ${failure.message}") failures)}
        '';
  in
    builtins.seq checked checked;
  builtContainers =
    lib.mapAttrs
    (name: definition: let
      container = checkedDefinition name definition;
    in
      import ../../lib/containers/build.nix {
        inherit lib pkgs container oci systemIdentity;
      })
    cfg.definitions;
in {
  options.aos.containers = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = pkgs.stdenv.hostPlatform.isLinux;
      description = "Whether this system evaluation exposes associated OCI container artifacts.";
    };

    default = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "aos";
      description = "Name of the container associated with this system variant by default.";
    };

    definitions = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule containerSchema);
      default = {};
      internal = true;
      description = "Strict OCI artifact definitions evaluated with this system variant.";
    };
  };

  options.system.build.containers = lib.mkOption {
    type = lib.types.attrsOf lib.types.anything;
    default = {};
    readOnly = true;
    description = "OCI artifacts derived from this evaluated system configuration.";
  };

  options.system.build.defaultContainer = lib.mkOption {
    type = lib.types.nullOr lib.types.anything;
    default = null;
    readOnly = true;
    description = "Default OCI artifact associated with this system variant.";
  };

  config = lib.mkIf cfg.enable {
    aos.containers.definitions.aos = defaultAosDefinition;

    assertions =
      [
        {
          assertion = cfg.default == null || builtins.hasAttr cfg.default cfg.definitions;
          message = "aos.containers.default must name an enabled container definition";
        }
      ]
      ++ builtins.concatMap
      (name:
        map
        (assertion: assertion // {message = "container '${name}': ${assertion.message}";})
        (definitionAssertions cfg.definitions.${name}))
      (builtins.attrNames cfg.definitions);

    system.build.containers = builtContainers;
    system.build.defaultContainer =
      if cfg.default == null
      then null
      else builtContainers.${cfg.default};
  };
}
