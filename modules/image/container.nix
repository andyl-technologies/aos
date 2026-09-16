##! Target-neutral selection of a package-owned container artifact backend.
##!
##! The base module knows only the selected backend value and checked package
##! projections. OCI layout, runtime initialization, and platform mapping stay
##! inside the backend package.
{
  config,
  checkedPackageProjections ? [],
  lib,
  pkgs,
  systemName,
  ...
}: let
  cfg = config.aos.containers or null;
  enabled = cfg != null && cfg.enable;
  backend =
    if enabled
    then cfg.backend
    else null;
  targetPlatform = {
    os = pkgs.stdenv.hostPlatform.constraints.os;
    cpu = pkgs.stdenv.hostPlatform.constraints.cpu;
    abi = pkgs.stdenv.hostPlatform.constraints.abi;
    features = pkgs.stdenv.hostPlatform.constraints.features;
  };
  mkReferenceGraph = import ../../lib/build/reference-graph.nix {
    inherit lib;
    inherit (pkgs.buildPackages) mkDerivation coreutils jq;
  };
  runtimeClosureAudit = args:
    import ../../lib/build/runtime-closure-audit.nix args;
  defaultDefinition =
    if enabled
    then
      (backend.defaultDefinition {
        inherit lib pkgs targetPlatform;
        goldenRoots = config.environment.systemPackages;
        evidenceOverrides = [];
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
            mkReferenceGraph
            runtimeClosureAudit
            ;
          buildPackages = pkgs.buildPackages;
          packageProjections = checkedPackageProjections;
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
        assertion = cfg.default == null || builtins.hasAttr cfg.default cfg.definitions;
        message = "aos.containers.default must name an enabled container definition";
      }
    ];

    system.build.containers = builtContainers;
    system.build.defaultContainer =
      if cfg.default == null
      then null
      else builtContainers.${cfg.default};
  };
}
