##! modules/base/config-eval.nix — on-host configuration evaluation
##!
##! Configures the package-owned stage-2 evaluator that drives the resolve/eval
##! fixed point over the in-image base library, the
##! per-package `config` modules fetched from the registry, and the delivered
##! leaf `host.nix` (or the image-authored empty module when no operator input
##! exists). It emits ONLY a manifest (`/run/aos/manifest.json`) and
##! never activates — a failed eval or fetch leaves the baked or previously
##! activated configuration running for the operator to fix `host.nix`.
##!
##! This is a structural boot service. Every AOS system runs the evaluator so a
##! first boot or image transition with no delivered input still commits a
##! base-only config generation before the image transition is finalized.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.config.evalAtBoot;
  provisioningStateDir = config.aos.provisioning.stateDir;
in {
  options.aos.config.evalAtBoot = {
    hostNix = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos-metadata/host.nix";
      description = ''
        Path to the leaf `host.nix` delivered by the initrd metadata agent. The
        metadata stash lives under `/run`, which is moved into the real root
        during switch_root. When neither this path nor the durable runtime cache
        exists, evaluation uses the image-authored empty module.
      '';
    };

    trust = lib.mkOption {
      type = lib.types.enum ["platform" "signed"];
      default = "platform";
      description = ''
        Authentication policy for the delivered `host.nix`.

        `platform` trusts configuration obtained by the initrd metadata agent
        from the deployment platform. This is the default for cloud images:
        control of instance user-data is already part of the cloud control
        plane's authority, so one unmodified golden image can configure every
        instance.

        `signed` is the fail-closed mode for deployments that do not trust
        their metadata transport. The initrd verifies the complete provisioning
        input against `aos.apm.configKeys` before any storage mutation. Missing
        keys, missing signatures, and invalid signatures all prevent boot-time
        provisioning.
      '';
    };

    baseLib = lib.mkOption {
      type = lib.types.nullOr (lib.types.oneOf [lib.types.package lib.types.str]);
      default = null;
      internal = true;
      readOnly = true;
      description = ''
        Store path of the in-image, ABI-pinned module library passed to the
        evaluator as `--base-lib`. Image construction supplies the derivation;
        the library's on-host entrypoint supplies its own realized path as a
        string so evaluation does not copy it to a new store path. This is
        image-owned and cannot be replaced by host.nix.
      '';
    };

    baseLibAbiHash = lib.mkOption {
      type = lib.types.strMatching "sha256:[0-9a-f]{64}";
      internal = true;
      readOnly = true;
      description = ''
        Canonical hash of the in-image module ABI integer and option
        schema. This is computed by the options-only base-library evaluation.
      '';
    };

    moduleAbi = lib.mkOption {
      type = lib.types.int;
      default = 1;
      description = ''
        Fallback base-lib `module_abi` used when `/etc/os-release` does not
        carry `AOS_MODULE_ABI`. The resolver gates every config module against
        this value before it enters the eval.
      '';
    };

    manifest = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos/manifest.json";
      description = "Where the converged manifest is written (only on success).";
    };
  };

  config = {
    aos.packageRuntime.configurationEvaluation = {
      enable = true;
      hostNix = cfg.hostNix;
      baseLib =
        if cfg.baseLib == null
        then "/aos-toplevel/base-lib"
        else toString cfg.baseLib;
      moduleAbi = cfg.moduleAbi;
      manifest = cfg.manifest;
      evalRoot = "/run/aos-eval";
      provisioningState = provisioningStateDir;
      imageVersion = config.aos.system.version;
      measuredBoot = config.aos.boot.secureBoot.measuredBoot.enable;
      pcrPublicKey = config.aos.boot.secureBoot.measuredBoot._effectivePcrPublicKey;
    };

    assertions = [
      {
        assertion = cfg.baseLib != null;
        message = "aos.config.evalAtBoot.baseLib must be set to the in-image base library store path.";
      }
      {
        assertion =
          cfg.trust
          != "signed"
          || builtins.attrNames config.aos.apm.configKeys != [];
        message = "aos.config.evalAtBoot.trust = \"signed\" requires at least one aos.apm.configKeys trust anchor.";
      }
    ];
  };
}
