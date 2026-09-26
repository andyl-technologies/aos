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
  cfg =
    config.aos.containers or {
      enable = false;
      default = null;
      definitions = {};
    };
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
        systemPackageSlice = cfg.systemPackageSlice;
      })
      .config
      // {
        # Only the system-derived definition inherits image fixture policy.
        runtimePolicy = {
          inherit (config.aos.image) allowTestArtifacts testArtifactRoots;
        };
      }
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
      {
        assertion = let
          systemPaths = map builtins.toString config.environment.systemPackages;
        in
          builtins.all (package: builtins.elem (builtins.toString package) systemPaths) cfg.systemPackageSlice;
        message = "aos.containers.systemPackageSlice must select packages from environment.systemPackages";
      }
    ];

    system.build.containers = builtContainers;
    system.build.defaultContainer =
      if defaultContainerName == null
      then null
      else builtContainers.${defaultContainerName};
  };
}
