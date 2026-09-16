##! Deployment inputs for structured ability activation.
{
  config,
  pkgs,
  lib,
  ...
}: let
  buildPkgs = pkgs.buildPackages;
  oci = import ../../lib/build/oci {
    inherit lib;
    inherit (buildPkgs) mkDerivation coreutils findutils gzip jq tar;
    abilityContractValidator = buildPkgs.aos-ability-contract-validator;
  };
  bootPlatform =
    if pkgs.stdenv.hostPlatform.system == "x86_64-linux"
    then {
      os = "linux";
      architecture = "amd64";
    }
    else if pkgs.stdenv.hostPlatform.system == "aarch64-linux"
    then {
      os = "linux";
      architecture = "arm64";
    }
    else throw "bootable static ability contracts require a supported Linux image platform";
  staticAbilityContractBuild = oci.mkStaticAbilityContract {
    pname = "aos-host-static-abilities";
    artifactClass = "bootable";
    executionStage = "host";
    platform = bootPlatform;
    targetPlatform = {
      system = pkgs.stdenv.hostPlatform.constraints.os;
      architecture = pkgs.stdenv.hostPlatform.constraints.cpu;
    };
    packageRoots = config.environment.systemPackages;
    packageRegistry = pkgs;
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
