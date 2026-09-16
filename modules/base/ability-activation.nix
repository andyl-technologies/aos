##! Deployment inputs for structured ability activation.
{
  config,
  checkedPackageProjections ? [],
  pkgs,
  lib,
  ...
}: let
  buildPkgs = pkgs.buildPackages;
  selectedStaticContractBackend = config.aos.artifacts.staticContractBackend or null;
  staticContractBackend =
    if
      builtins.isAttrs selectedStaticContractBackend
      && (selectedStaticContractBackend._type or null) == "aos-package-artifact-backend"
    then selectedStaticContractBackend
    else throw "host static ability contracts require one selected package-owned artifact backend";
  targetPlatform = {
    os = pkgs.stdenv.hostPlatform.constraints.os;
    cpu = pkgs.stdenv.hostPlatform.constraints.cpu;
    abi = pkgs.stdenv.hostPlatform.constraints.abi;
    features = pkgs.stdenv.hostPlatform.constraints.features;
  };
  mkReferenceGraph = import ../../lib/build/reference-graph.nix {
    inherit lib;
    inherit (buildPkgs) mkDerivation coreutils jq;
  };
  staticAbilityContractBuild = staticContractBackend.buildStaticContract {
    inherit lib targetPlatform mkReferenceGraph;
    buildPackages = buildPkgs;
    pname = "aos-host-static-abilities";
    artifactClass = "bootable";
    executionStage = "host";
    packageProjections = checkedPackageProjections;
    runtimeRoots = config.environment.systemPackages;
  };
  staticAbilityContractSource = staticAbilityContractBuild.artifact;
  # The base library captures the image-built contract under this key. Runtime
  # evaluation reuses that path and leaves the build-only package thunks lazy.
  staticAbilityContract =
    if config.aos.config.frozenArtifacts ? "host-static-ability-contract"
    then let
      path = config.aos.config.frozenArtifacts.host-static-ability-contract;
    in {
      type = "derivation";
      name = "host-static-ability-contract";
      outPath = path;
      __toString = _: path;
    }
    else staticAbilityContractSource;

in {
  options = {
    aos.abilities.activationInput = lib.mkOption {
      type = lib.types.nullOr lib.types.attrs;
      default = null;
      description = ''
        Immutable desired-state and authenticated-policy sidecars used to plan
        structured ability effects. The on-host evaluator replaces package
        coordinates from the authenticated runtime resolution and validates
        the complete activation input before publishing a configuration generation.
      '';
    };

    aos.boot.initrd.abilityHandoff.enable = lib.mkEnableOption ''
      the signed initrd-to-host ability ownership handoff
    '';

    system.build.staticAbilityContract = lib.mkOption {
      type = lib.types.package;
      readOnly = true;
      description = ''
        Static host-stage ability declarations in the immutable system image.
        Required runtime inputs remain explicit deployment obligations and the
        contract carries no runtime grants.
      '';
    };
  };

  config = {
    # Runtime providers own their private subdirectories. The generic engine
    # owns only the shared roots and keeps credential and policy material
    # inaccessible to provider identities.
    environment.etc."tmpfiles.d/aos-ability-runtime.conf".text = ''
      d /var/lib/aos/ability-runtime                    0711 root root -
      d /var/lib/aos/ability-runtime/credential-sources 0700 root root                   -
      d /var/lib/aos/ability-runtime/credentials        0700 root root                   -
      d /var/lib/aos/ability-runtime/endpoints          0700 root root                   -
      d /var/lib/aos/ability-runtime/network-policy     0700 root root                   -
      d /var/lib/aos/ability-runtime/storage            0711 root root                   -
    '';

    system.build.staticAbilityContract = staticAbilityContract;
    aos.boot.initrd.extraPackages = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable [
      pkgs.aos.packageRuntime
    ];
  };
}
