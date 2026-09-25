##! Target-neutral selection of a package-owned container artifact backend.
##!
##! The base module knows only the selected backend value and checked package
##! projections. OCI layout, runtime initialization, and platform mapping stay
##! inside the backend package.
{
  config,
  lib,
  pkgs,
  systemName,
  ...
}: let
  cfg = config.aos.containers or {
    enable = false;
    default = null;
    definitions = {};
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
    secureBootSource = retainedSource "secure-boot" ../base/secure-boot.nix;
    firmwareEnrollmentSource = pkgs.mkDerivation {
      pname = "aos-container-source-firmware-enrollment";
      version = "1";
      src = null;
      buildDeps = [pkgs.coreutils];
      runtimeDeps = [];
      propagatedDeps = [];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/source"
            cp ${config.aos.boot.secureBoot.enrollAuthDir}/*.auth "$out/source/"
          '';
        }
      ];
    };
  in
    [
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
    ]
    ++ lib.optionals config.aos.boot.secureBoot.enable [
      {
        output = artifacts.secure-boot-enroll;
        outputName = "out";
        pname = "aos-sb-enroll";
        inherit version;
        licenses = ["Apache-2.0"];
        sources = [secureBootSource];
      }
    ]
    # Fixture keys do not produce a public enrollment artifact. Release
    # finalization does, and its container evidence must retain that output.
    ++ lib.optionals (
      config.aos.boot.secureBoot.enable
      && config.aos.boot.secureBoot.externalFinalization.enable
    ) [
      {
        output = artifacts.secure-boot-enrollment-public;
        outputName = "out";
        pname = "aos-public-firmware-enrollment";
        version = "1";
        licenses = ["Apache-2.0"];
        sources = [secureBootSource firmwareEnrollmentSource];
      }
    ];
  enabled = cfg.enable;
  defaultContainerName =
    if !enabled || cfg.default == null
    then null
    else builtins.unsafeDiscardStringContext cfg.default;
  backend = config.aos.artifacts.backend;
  targetPlatform = {
    os = pkgs.stdenv.hostPlatform.constraints.os;
    cpu = pkgs.stdenv.hostPlatform.constraints.cpu;
    abi = pkgs.stdenv.hostPlatform.constraints.abi;
    features = pkgs.stdenv.hostPlatform.constraints.features;
  };
  runtimeClosureAudit = lib.build.runtimeClosureAudit;
  defaultDefinition =
    if enabled
    then
      (backend.defaultDefinition {
        inherit lib pkgs targetPlatform;
        goldenRoots = config.environment.systemPackages;
        inherit evidenceOverrides;
      })
      .config
    else null;
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
  builtContainers =
    if !enabled
    then {}
    else
      lib.mapAttrs
      (name: container:
        backend.buildContainer {
          inherit
            lib
            pkgs
            container
            systemIdentity
            runtimeClosureAudit
            ;
          buildPackages = pkgs.buildPackages;
          definitionAttribute = "systems.${systemName}.build.containers.${name}";
        })
      cfg.definitions;
in {
  options.system.build = {
    containers = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
      readOnly = true;
      description = "Container artifacts derived by the selected package backend.";
    };

    defaultContainer = lib.mkOption {
      type = lib.types.nullOr lib.types.anything;
      default = null;
      readOnly = true;
      description = "Default container artifact associated with this system variant.";
    };
  };

  config = lib.mkIf enabled {
    aos.containers.definitions.aos = lib.mkDefault defaultDefinition;

    assertions = [
      {
        assertion = (backend._type or null) == "aos-package-artifact-backend";
        message = "container artifacts require one selected package-owned backend";
      }
      {
        assertion = builtins.match "[A-Za-z_][A-Za-z0-9_-]*" systemName != null;
        message = "system variant names with containers must be canonical Nix attribute identifiers";
      }
      {
        assertion = defaultContainerName == null || builtins.hasAttr defaultContainerName cfg.definitions;
        message = "aos.containers.default must name an enabled container definition";
      }
    ];

    system.build.containers = builtContainers;
    system.build.defaultContainer =
      if defaultContainerName == null
      then null
      else builtContainers.${defaultContainerName};
  };
}
