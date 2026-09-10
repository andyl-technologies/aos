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
  abilityPackages =
    builtins.filter (
      package:
        builtins.isAttrs package
        && package ? abilities
        && (package.abilities.passthru.abilityPackage or false)
    )
    config.environment.systemPackages;
  staticAbilityContract = oci.mkStaticAbilityContract {
    pname = "aos-host-static-abilities";
    artifactClass = "bootable";
    executionStage = "host";
    platform = bootPlatform;
    packages =
      map (package: {
        payload = package;
        manifest = package.abilities;
      })
      abilityPackages;
    runtimeRoots = config.environment.systemPackages;
  };
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
    system.build.staticAbilityContract = staticAbilityContract;

    environment.etc."aos/static-ability-contract.json" = {
      source = "${staticAbilityContract}/contract.json";
      mode = "0444";
    };
  };
}
