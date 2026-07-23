##! modules/base/config-eval.nix — on-host configuration evaluation
##!
##! Authors `aos-eval.service`: the stage-2 systemd unit that drives the
##! resolve↔eval fixpoint (`apm __eval`) over the in-image base library, the
##! per-package `config` modules fetched from the registry, and the delivered
##! leaf `host.nix`. It emits ONLY a manifest (`/run/aos/manifest.json`) and
##! never activates — a failed eval or fetch leaves the baked or previously
##! activated configuration running for the operator to fix `host.nix`.
##!
##! This is a structural boot service. Every AOS system carries the evaluator;
##! `ConditionPathExists` makes hosts without a delivered `host.nix` a clean
##! no-op on the baked generation.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.config.evalAtBoot;
in {
  options.aos.config.evalAtBoot = {
    hostNix = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos-metadata/host.nix";
      description = ''
        Path to the leaf `host.nix` delivered by the initrd metadata agent. The
        metadata stash lives under `/run`, which is moved into the real root
        during switch_root. The service is `ConditionPathExists`-guarded on
        this path, so with no `host.nix` the eval is a clean no-op.
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
        their metadata transport. It requires a detached `host.nix.sig` that
        verifies against a key in `aos.apm.configKeys`. Missing keys, missing
        signatures, and invalid signatures all prevent evaluation.
      '';
    };

    baseLib = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = ''
        Store path of the in-image, ABI-pinned module library passed to the
        evaluator as `--base-lib`.
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

    desired = lib.mkOption {
      type = lib.types.str;
      default = "/etc/aos/packages.d/desired.toml";
      description = "Desired-package TOML whose `packages` seed the working set.";
    };

    manifest = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos/manifest.json";
      description = "Where the converged manifest is written (only on success).";
    };
  };

  config = {
    assertions = [
      {
        assertion = cfg.baseLib != "";
        message = "aos.config.evalAtBoot.baseLib must be set to the in-image base library store path.";
      }
      {
        assertion =
          cfg.trust != "signed"
          || builtins.attrNames config.aos.apm.configKeys != [];
        message = "aos.config.evalAtBoot.trust = \"signed\" requires at least one aos.apm.configKeys trust anchor.";
      }
    ];

    systemd.services.aos-eval = {
      description = "Evaluate host configuration to a converged manifest";
      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      after = [
        "network-online.target"
        "nix-overlay-setup.service"
        "aos-config-seed.service"
        "aos-seed-profiles.service"
      ];
      before = [
        "aos-install-baked-packages.service"
        "aos-graph-compile.service"
        "multi-user.target"
      ];
      # No host.nix ⇒ nothing to evaluate ⇒ clean no-op.
      unitConfig.ConditionPathExists = cfg.hostNix;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Per-eval hardened resource budget. A runaway is OOM- or
        # timeout-killed by the cgroup.
        RuntimeMaxSec = 120;
        MemoryMax = "2G";
        MemoryHigh = "1536M";
        TasksMax = 4096;
        # Hardened scope: inputs read-only, only /run/aos* writable.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ReadWritePaths = ["/run/aos" "/run/aos-eval"];
        # Best-effort: a failed eval must never fail the boot. The manifest is
        # the only product, and its absence makes the downstream a no-op.
        SuccessExitStatus = "0 1";
      };
      script = ''
        set -u
        mkdir -p /run/aos-eval /run/aos
        # Stage the metadata-agent-owned input into the hardened eval root.
        # Signed mode authenticates the sibling SSHSIG before evaluation;
        # platform mode relies on the deployment control plane that supplied
        # the initrd metadata.
        cp -f "${cfg.hostNix}" /run/aos-eval/host.nix
        cp -f "${cfg.hostNix}.sig" /run/aos-eval/host.nix.sig 2>/dev/null || true

        # Prefer the image's recorded module_abi; fall back to the option.
        module_abi="${toString cfg.moduleAbi}"
        if [ -r /etc/os-release ]; then
          # shellcheck disable=SC1091
          . /etc/os-release
          if [ -n "''${AOS_MODULE_ABI:-}" ]; then
            module_abi="$AOS_MODULE_ABI"
          fi
        fi

        desired_arg=""
        if [ -r "${cfg.desired}" ]; then
          desired_arg="--desired ${cfg.desired}"
        fi

        # Failure-safe: on any error apm __eval writes no manifest and exits
        # non-zero; SuccessExitStatus keeps the boot green either way.
        ${pkgs.aos}/bin/apm __eval \
          --host-nix /run/aos-eval/host.nix \
          --base-lib "${cfg.baseLib}" \
          --module-abi "$module_abi" \
          --out "${cfg.manifest}" \
          --eval-root /run/aos-eval \
          ${lib.optionalString (cfg.trust == "signed") "--require-signed-host-nix --trusted-config-keys-dir /etc/apm/trusted-config-keys.d"} \
          $desired_arg || exit 1
      '';
    };
  };
}
