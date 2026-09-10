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
  staticAbilityContractSource = oci.mkStaticAbilityContract {
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

  initrdActivationSelection = {
    schema = "aos.ability.initrd-activation-selection/v1";
    execution_stage = "initrd";
    disposition =
      if config.aos.abilities.initrdActivationInput == null
      then "none"
      else "required";
    activation = config.aos.abilities.initrdActivationInput;
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

    aos.abilities.initrdActivationInput = lib.mkOption {
      type = lib.types.nullOr lib.types.attrs;
      default = null;
      description = ''
        Authenticated initrd-stage activation input embedded in the signed
        initrd. A null value records an explicit no-activation disposition;
        file absence never authorizes a no-op.
      '';
    };

    aos.boot.initrd.abilityHandoff.enable = lib.mkEnableOption ''
      the signed initrd-to-host ability ownership handoff
    '';

    system.build.initrdAbilityActivationSelection = lib.mkOption {
      type = lib.types.attrs;
      readOnly = true;
      internal = true;
      description = ''
        Closed initrd activation selection before the initrd builder binds the
        exact static ability contract digest.
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
    system.build.initrdAbilityActivationSelection = initrdActivationSelection;

    assertions = [
      {
        assertion =
          config.aos.boot.initrd.abilityHandoff.enable
          || config.aos.abilities.initrdActivationInput == null;
        message = "initrd ability activation input requires the initrd-to-host ownership handoff";
      }
    ];

    aos.boot.initrd.extraPackages = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable [
      pkgs.aos.packageRuntime
    ];

    boot.initrd.systemd.services.aos-ability-initrd-controller = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable {
      description = "Execute and release initrd-stage ability ownership";
      requiredBy = [
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
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
        # Keep the successful producer active so the later switch-root target
        # cannot start a second producer after the checkpoint was published.
        RemainAfterExit = true;
      };
      script = ''
        exec ${pkgs.aos.packageRuntime}/bin/.aos-package-runtime-unwrapped \
          __ability-stage-run \
          --stage initrd \
          --root /sysroot \
          --image-profile /sysroot/var/lib/profiles/image \
          --input /etc/aos/initrd-ability-activation.json
      '';
    };

    # A separate read-only validator keeps switch-root ordered after evidence
    # authentication. Requires+After makes controller failure, an absent
    # checkpoint, or a mismatched durable journal fail the target transaction.
    boot.initrd.systemd.services.aos-ability-initrd-handoff-barrier = lib.mkIf config.aos.boot.initrd.abilityHandoff.enable {
      description = "Authenticate released initrd ability ownership";
      requiredBy = [
        "initrd-fs.target"
        "initrd-switch-root.target"
      ];
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
