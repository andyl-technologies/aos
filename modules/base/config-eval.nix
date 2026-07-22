##! modules/base/config-eval.nix — RFC-0011 on-host config evaluation
##!
##! Authors `aos-eval.service`: the stage-2 systemd unit that drives the
##! resolve↔eval fixpoint (`apm __eval`) over the in-image base library, the
##! per-package `config` modules fetched from the registry, and the verified
##! leaf `host.nix`. It emits ONLY a manifest (`/run/aos/manifest.json`) and
##! never activates — a failed eval or fetch leaves the box live on the gen-0
##! seed for the operator to fix `host.nix`.
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
      default = "/etc/aos/host.nix";
      description = ''
        Path to the verified leaf `host.nix` delivered by the metadata agent. The service
        is `ConditionPathExists`-guarded on this path, so with no `host.nix` the
        eval is a clean no-op.
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
    ];

    systemd.services.aos-eval = {
      description = "RFC-0011 on-host config evaluation (resolve↔eval fixpoint)";
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
        # Per-eval hardened budget — the limits ARE the perf budget
        # (build-spec §3). A runaway is OOM-/timeout-killed by the cgroup.
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
        # Stage the UNTRUSTED host.nix + its detached operator signature into the
        # eval root. apm __eval authenticates the SSHSIG against the image-baked
        # trusted-config-keys.d BEFORE evaluating (the stage-2 trust gate); a
        # missing/bad signature yields no manifest (failure-safe). The signature
        # is read from <host.nix>.sig; stage it best-effort (its absence makes the
        # gate fail closed with MissingSignature, which is correct).
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
          --trusted-config-keys-dir /etc/apm/trusted-config-keys.d \
          $desired_arg || exit 1
      '';
    };
  };
}
