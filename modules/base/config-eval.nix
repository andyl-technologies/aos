##! modules/base/config-eval.nix — on-host configuration evaluation
##!
##! Authors `aos-eval.service`: the stage-2 systemd unit that drives the
##! resolve↔eval fixpoint (`apm __eval`) over the in-image base library, the
##! per-package `config` modules fetched from the registry, and the delivered
##! leaf `host.nix` (or the image-authored empty module when no operator input
##! exists). It emits ONLY a manifest (`/run/aos/manifest.json`) and
##! never activates — a failed eval or fetch leaves the baked or previously
##! activated configuration running for the operator to fix `host.nix`.
##!
##! This is a structural boot service. Every AOS system runs the evaluator so a
##! first boot or image transition with no delivered input still commits a
##! base-only config generation before sd-boot blesses the image.
{
  config,
  lib,
  pkgs,
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
      type = lib.types.nullOr lib.types.package;
      default = null;
      internal = true;
      readOnly = true;
      description = ''
        Store path of the in-image, ABI-pinned module library passed to the
        evaluator as `--base-lib`. This is image-owned and cannot be replaced
        by host.nix.
      '';
    };

    baseLibAbiHash = lib.mkOption {
      type = lib.types.strMatching "sha256:[0-9a-f]{64}";
      internal = true;
      readOnly = true;
      description = ''
        Canonical RFC-0011 hash of the in-image module ABI integer and option
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

    # Records the reboot boundary that requires configuration to be rebound to
    # the newly running image. The normal eval -> graph -> activate pipeline
    # below performs the work; this early idempotent predicate makes the image
    # transition explicit and auditable without a reboot-spanning transaction.
    systemd.services.aos-firstboot-reeval = {
      description = "Detect a running-image change requiring host re-evaluation";
      wantedBy = ["multi-user.target"];
      requires = ["aos-seed-profiles.service"];
      after = ["aos-seed-profiles.service"];
      before = [
        "aos-host-config-restore.service"
        "aos-eval.service"
        "multi-user.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        RuntimeDirectory = "aos";
      };
      script = ''
        set -eu
        image_state=/var/lib/profiles/image/state.json
        config_state=/var/lib/profiles/system/state.json
        [ -s "$image_state" ] && [ -s "$config_state" ] || exit 1
        running=$(${pkgs.jq}/bin/jq -er '.running' "$image_state")
        parent=$(${pkgs.jq}/bin/jq -er \
          '.current as $current | [.generations[] | select(.number == $current) | .image_gen_parent][0] // 0' \
          "$config_state")
        pending=$(${pkgs.jq}/bin/jq -er '.pending // 0' "$image_state")
        if [ "$running" != "$parent" ] || [ "$pending" -ne 0 ]; then
          printf '%s\n' "$running" > /run/aos/image-reeval-required
        else
          rm -f /run/aos/image-reeval-required
        fi
      '';
    };

    systemd.services.aos-provisioning-persist = {
      description = "Persist provisioning evidence and manual repart definitions";
      wantedBy = ["multi-user.target"];
      requires = ["local-fs.target"];
      after = [
        "local-fs.target"
        "aos-config-seed.service"
      ];
      before = [
        "aos-host-config-restore.service"
        "aos-eval.service"
        "multi-user.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "aos-provisioning";
        StateDirectoryMode = "0700";
      };
      script = ''
        ${pkgs.aos}/bin/aos metadata persist-provisioning \
          --state-dir ${provisioningStateDir} \
          --module-abi ${toString cfg.moduleAbi} \
          --image-version ${config.aos.system.version}
      '';
    };

    systemd.services.aos-host-config-restore = {
      description = "Restore the last fully evaluated host input";
      wantedBy = ["multi-user.target"];
      after = ["aos-provisioning-persist.service" "aos-firstboot-reeval.service"];
      before = [
        "aos-eval.service"
        "multi-user.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "aos-provisioning";
        StateDirectoryMode = "0700";
      };
      script = ''
        if [ ! -e "${cfg.hostNix}" ]; then
          ${pkgs.aos}/bin/aos metadata restore-runtime \
            --state-dir ${provisioningStateDir} \
            || echo "aos-eval: cached host input is unavailable or invalid; retaining the active generation" >&2
        fi
      '';
    };

    systemd.services.aos-eval = {
      description = "Evaluate host configuration to a converged manifest";
      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      requires = ["aos-host-config-restore.service" "aos-firstboot-reeval.service"];
      after = [
        "network-online.target"
        "nix-overlay-setup.service"
        "aos-config-seed.service"
        "aos-seed-profiles.service"
        "aos-host-config-restore.service"
      ];
      before = [
        "aos-install-baked-packages.service"
        "aos-graph-compile.service"
        "multi-user.target"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Per-eval hardened resource budget. A runaway is OOM- or
        # timeout-killed by the cgroup.
        TimeoutStartSec = "120s";
        MemoryMax = "2G";
        MemoryHigh = "1536M";
        TasksMax = 4096;
        # These paths must exist before systemd constructs the service's mount
        # namespace for ReadWritePaths. They are runtime state, not image
        # contents, so create them for every boot.
        RuntimeDirectory = ["aos" "aos-eval"];
        # Hardened scope: inputs read-only, only /run/aos* writable.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        # The service's resolver must import newly fetched config outputs and
        # content-address the accepted host/facts inputs in the local store.
        # Keep the store mount writable for those Nix operations, while
        # bind-remounting the evaluator's pre-existing authority inputs read-only.
        # Prefix the optional operator input with `-`: systemd still mounts it
        # read-only when present, but a no-input boot reaches the image-default
        # fallback rather than failing namespace setup.
        ReadOnlyPaths = ["-${cfg.hostNix}"] ++ lib.optional (cfg.baseLib != null) (toString cfg.baseLib);
        ReadWritePaths = ["/nix" "/run/aos" "/run/aos-eval"];
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@clock @cpu-emulation @debug @keyring @mount @obsolete @privileged @raw-io @reboot @resources @swap"
        ];
        SystemCallErrorNumber = "EPERM";
        # A failed eval is visible as a failed unit. The boot remains reachable
        # because multi-user.target Wants (rather than Requires) this service;
        # downstream ConditionPathExists guards prevent any configuration swap.
      };
      script = ''
        set -u
        mkdir -p /run/aos-eval /run/aos
        # Confirm delivered bytes against the initrd authorization result. If
        # neither metadata nor the durable last-known-good cache supplied an
        # operator module, use a narrowly marked image-authored empty module.
        # That no-input arm still evaluates and activates, binding a fresh
        # config generation to the running image before boot assessment.
        image_default_arg=""
        if [ -e "${cfg.hostNix}" ]; then
          ${pkgs.aos}/bin/aos metadata verify-binding
          cp -f "${cfg.hostNix}" /run/aos-eval/host.nix
        else
          printf '{}\n' > /run/aos-eval/host.nix
          image_default_arg="--image-default-host"
        fi
        rm -f "${cfg.manifest}" /run/aos/graph.json

        # Prefer the immutable running image's os-release. `/etc/os-release`
        # is a configuration overlay and can still belong to the prior image
        # during the first boot after an A/B transition.
        module_abi="${toString cfg.moduleAbi}"
        if [ -r /aos-toplevel/os-release ]; then
          # shellcheck disable=SC1091
          . /aos-toplevel/os-release
          if [ -n "''${AOS_MODULE_ABI:-}" ]; then
            module_abi="$AOS_MODULE_ABI"
          fi
        fi

        desired_arg=""
        if [ -r "${cfg.desired}" ]; then
          desired_arg="--desired ${cfg.desired}"
        fi

        # Failure-safe: on any error apm __eval writes no manifest and exits
        # non-zero. Wants ordering keeps the boot reachable; downstream
        # manifest guards make the attempted switch a no-op.
        ${pkgs.aos}/bin/apm __eval \
          --host-nix /run/aos-eval/host.nix \
          --base-lib "${cfg.baseLib}" \
          --module-abi "$module_abi" \
          --out "${cfg.manifest}" \
          --eval-root /run/aos-eval \
          $image_default_arg \
          $desired_arg || exit 1
      '';
    };

    # A pending image is blessed only after the host configuration pipeline has
    # successfully rebound `/etc` to the image that actually booted. This is
    # also the recovery point for sd-boot fallback: if `pending != running`, the
    # failed candidate is demoted and the known-good running image becomes the
    # durable default again.
    systemd.services.aos-image-boot-commit = {
      description = "Commit a successful RFC-0011 image transition";
      wantedBy = ["multi-user.target"];
      after = [
        "aos-firstboot-reeval.service"
        "aos-graph-compile.service"
        "aos-activate.service"
        "aos-config.target"
      ];
      requires = ["aos-graph-compile.service"];
      before = ["multi-user.target"];
      unitConfig.ConditionPathExists = "/run/aos/image-reeval-required";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        state=/var/lib/profiles/image/state.json
        running=$(${pkgs.jq}/bin/jq -er '.running' "$state")
        pending=$(${pkgs.jq}/bin/jq -er '.pending // 0' "$state")
        current=$(${pkgs.jq}/bin/jq -er '.current' /var/lib/profiles/system/state.json)
        parent=$(${pkgs.jq}/bin/jq -er \
          '.current as $current | .generations[] | select(.number == $current) | .image_gen_parent // 0' \
          /var/lib/profiles/system/state.json)
        if [ ! -s "/var/lib/profiles/system/gen-$current/manifest.json" ]; then
          echo "aos-image-boot-commit: running config generation has no committed manifest" >&2
          exit 1
        fi
        if [ "$parent" != "$running" ]; then
          echo "aos-image-boot-commit: configuration has not rebound to running image $running" >&2
          exit 1
        fi
        entry=$(${pkgs.jq}/bin/jq -er \
          --argjson running "$running" \
          '.generations[] | select(.number == $running) | .uki_path' "$state")

        # Bless only a pending candidate that actually became the running
        # image. When sd-boot has already fallen back, the running known-good
        # entry is normally uncounted and `set-successful` would fail; in that
        # arm we merely restore it as the durable default below.
        if [ "$pending" -eq "$running" ]; then
          ${pkgs.systemd}/bin/bootctl set-successful
        fi

        # A failed pending candidate may already have fallen back to `running`.
        # Resolve the successful entry's stable name after boot-count renaming.
        case "$entry" in
          *+*) stable=''${entry%%+*}.efi ;;
          *) stable=$entry ;;
        esac
        ${pkgs.systemd}/bin/bootctl set-default "''${stable##*/}"

        ${pkgs.jq}/bin/jq --argjson running "$running" \
          '.default = $running | .pending = null' "$state" > "''${state}.new"
        ${pkgs.coreutils}/bin/sync -f "''${state}.new"
        mv "''${state}.new" "$state"
        ${pkgs.coreutils}/bin/sync -f "$(dirname "$state")"
        rm -f /run/aos/image-reeval-required
      '';
    };

    systemd.services.aos-host-config-cache = {
      description = "Cache the last fully evaluated host input";
      wantedBy = ["multi-user.target"];
      after = ["aos-eval.service"];
      before = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        StateDirectory = "aos-provisioning";
        StateDirectoryMode = "0700";
      };
      script = ''
        if [ -s "${cfg.manifest}" ] && [ -s "${cfg.hostNix}" ]; then
          ${pkgs.aos}/bin/aos metadata cache-runtime \
            --state-dir ${provisioningStateDir}
        fi
      '';
    };
  };
}
