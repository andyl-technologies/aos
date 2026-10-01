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
  systemName,
  ...
}: let
  cfg = config.aos.containers;
  buildPackages = pkgs.buildPackages;
  containerSchema = import ../../lib/containers/schema.nix;
  # Archive and inventory builders execute on the build machine, even when
  # their payload contains binaries for a different architecture.
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (buildPackages) mkDerivation coreutils findutils gzip jq tar;
  };
  sourceInputs = {
    boot-storage = ../base/boot-storage.nix;
    mount-esp = ../base/mount-esp.sh.in;
    sync-esps = ../base/sync-esps.sh.in;
    secure-boot = ../base/secure-boot.nix;
  };
  buildRetainedSource = name: source:
    pkgs.writeTextFile {
      name = "aos-container-source-${name}";
      text = builtins.readFile source;
      destination = "/source/${builtins.baseNameOf source}";
    };
  evidenceOverrides = let
    artifacts = config.aos.config.artifacts;
    version = config.aos.system.version;
    bootStorageSource = config.aos.config.artifacts.container-source-boot-storage;
    secureBootSource = config.aos.config.artifacts.container-source-secure-boot;
    firmwareEnrollmentSource = config.aos.config.artifacts.container-source-firmware-enrollment;
  in
    [
      {
        output = artifacts.esp-mount;
        outputName = "out";
        pname = "aos-mount-esp";
        inherit version;
        licenses = ["Apache-2.0"];
        sources = [bootStorageSource config.aos.config.artifacts.container-source-mount-esp];
      }
      {
        output = artifacts.esp-sync;
        outputName = "out";
        pname = "aos-sync-esps";
        inherit version;
        licenses = ["Apache-2.0"];
        sources = [bootStorageSource config.aos.config.artifacts.container-source-sync-esps];
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
  buildFirmwareEnrollmentSource = pkgs.mkDerivation {
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
  defaultAosDefinition =
    (import ./_container-definition.nix {
      inherit lib pkgs evidenceOverrides;
      goldenRoots = config.environment.systemPackages;
      aosSystem = pkgs.stdenv.hostPlatform.system;
    })
    .config
    // {
      # Only the system-derived definition inherits image fixture policy.
      # Independently declared containers keep the schema's strict defaults.
      runtimePolicy = {
        inherit (config.aos.image) allowTestArtifacts testArtifactRoots;
      };
    };
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
        definitionAttribute = "systems.${systemName}.build.containers.${name}";
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
    # The manifest boundary also checks OCI invariants. Retain their exact
    # source evidence through the existing frozen artifact interface so stage
    # two checks these values without invoking a builder.
    aos.config._artifactSources =
      lib.mapAttrs' (name: source: let
        key = "container-source-${name}";
      in
        lib.nameValuePair key (
          if config.aos.config.frozenArtifacts ? ${key}
          then config.aos.config.frozenArtifacts.${key}
          else buildRetainedSource name source
        ))
      sourceInputs
      // lib.optionalAttrs (
        config.aos.boot.secureBoot.enable
        && config.aos.boot.secureBoot.externalFinalization.enable
      ) {
        container-source-firmware-enrollment =
          if config.aos.config.frozenArtifacts ? "container-source-firmware-enrollment"
          then config.aos.config.frozenArtifacts.container-source-firmware-enrollment
          else buildFirmwareEnrollmentSource;
      };

    aos.containers.definitions.aos = defaultAosDefinition;
    aos.containers.definitions.aos-hub =
      (import ../../containers/aos-hub.nix {
        inherit pkgs;
        aosSystem = pkgs.stdenv.hostPlatform.system;
      })
      .config;

    aos.containers.definitions.aos-hub-bootstrap =
      (import ../../containers/aos-hub-bootstrap.nix {
        inherit pkgs;
        aosSystem = pkgs.stdenv.hostPlatform.system;
      })
      .config;

    assertions =
      [
        {
          assertion = builtins.match "[A-Za-z_][A-Za-z0-9_-]*" systemName != null;
          message = "system variant names with containers must be canonical Nix attribute identifiers";
        }
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
