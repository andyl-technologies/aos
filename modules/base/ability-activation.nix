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

    systemd.services.aos-activate = {
      requires = ["systemd-tmpfiles-setup.service"];
      after = ["systemd-tmpfiles-setup.service"];
    };

    system.build.staticAbilityContract = staticAbilityContract;
    aos.boot.initrd.extraPackages = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable [
      pkgs.aos.packageRuntime
    ];

    boot.initrd.systemd.services.aos-ability-initrd-controller = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable {
      description = "Execute and release initrd-stage ability ownership";
      requiredBy = ["initrd-fs.target"];
      requires = [
        "mount-var.service"
        "nix-overlay-setup.service"
        "aos-seed-profiles.service"
        "aos-credential-recovery.service"
      ];
      after = [
        "mount-var.service"
        "nix-overlay-setup.service"
        "aos-seed-profiles.service"
        "aos-credential-recovery.service"
      ];
      before = [
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        # Keep the successful producer active through initrd-fs completion so
        # no dependency can start a second producer for the same checkpoint.
        RemainAfterExit = true;
      };
      script = ''
        exec ${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped \
          __ability-stage-run \
          --stage initrd \
          --root /sysroot \
          --image-profile /sysroot/var/lib/profiles/image \
          --resolved-stage /lib/aos/initrd/resolved-ability-stage.json
      '';
    };

    # A separate read-only validator makes initrd-fs fail before cleanup when
    # evidence authentication fails. Keeping only the Before edge to
    # initrd-switch-root lets isolation stop the validated dependency chain
    # before udev cleanup instead of retaining both sides of that transaction.
    boot.initrd.systemd.services.aos-ability-initrd-handoff-barrier = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable {
      description = "Authenticate released initrd ability ownership";
      requiredBy = ["initrd-fs.target"];
      requires = ["aos-ability-initrd-controller.service"];
      after = ["aos-ability-initrd-controller.service"];
      before = [
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
      unitConfig.DefaultDependencies = "no";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StandardOutput = "journal+console";
        StandardError = "journal+console";
      };
      script = ''
        exec ${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped \
          __ability-stage-validate \
          --from-stage initrd \
          --root /sysroot \
          --image-profile /sysroot/var/lib/profiles/image
      '';
    };

    systemd.services.aos-ability-host-receiver = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable {
      description = "Revalidate and receive initrd ability ownership";
      requiredBy = [
        "aos-eval.service"
        "aos-graph-compile.service"
        "aos-config.target"
      ];
      requires = [
        "local-fs.target"
        "aos-nix-db.service"
        "aos-credential-recovery.service"
      ];
      after = [
        "local-fs.target"
        "aos-nix-db.service"
        "aos-credential-recovery.service"
      ];
      before = [
        "aos-eval.service"
        "aos-graph-compile.service"
        "aos-config.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      unitConfig.RequiresMountsFor = "/var/lib/profiles/image";
      script = ''
        exec ${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped \
          __ability-stage-receive \
          --from-stage initrd \
          --image-profile /var/lib/profiles/image
      '';
    };

    environment.etc."aos/static-ability-contract.json" = {
      source = "${staticAbilityContract}/contract.json";
      mode = "0444";
    };
  };
}
