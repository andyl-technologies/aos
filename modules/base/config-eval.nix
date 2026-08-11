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
  exposedBundledPackages =
    lib.filterAttrs
    (_: package: package.bundle && (package.package ? expose))
    config.aos.packages;
  packageSeedReadinessUnits =
    lib.optionals (exposedBundledPackages != {}) ["aos-seed-baked-packages.service"];
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
      # aos-seed-profiles is a stage-1 unit and is deliberately absent after
      # switch-root. Depend on the durable /var substrate it produced instead;
      # requiring the vanished initrd unit causes systemd to drop this job and,
      # through aos-eval's Requires= edge, silently skips host activation.
      requires = ["local-fs.target"];
      after = ["local-fs.target"];
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

        # Reconcile the userspace-to-firmware selection journal before the
        # evaluation graph can fail. A crash can leave this intent after the
        # authenticated pending state or bootloader default was published. At
        # this point aos-seed-profiles has authenticated the image that really
        # booted, so the journal no longer needs to block an operator rollback.
        stable_entry_id() {
          name=$1
          case "$name" in
            */*|"") return 1 ;;
            *.efi) ;;
            *) return 1 ;;
          esac
          stem=''${name%.efi}
          case "$stem" in
            *+*)
              suffix=''${stem##*+}
              tries=''${suffix%%-*}
              case "$tries" in ""|*[!0-9]*) printf '%s\n' "$name"; return 0 ;; esac
              case "$suffix" in
                *-*)
                  completed=''${suffix#*-}
                  case "$completed" in ""|*[!0-9]*|*-*) printf '%s\n' "$name"; return 0 ;; esac
                  ;;
              esac
              printf '%s.efi\n' "''${stem%+*}"
              ;;
            *) printf '%s\n' "$name" ;;
          esac
        }
        transition_intent=/var/lib/profiles/image/.transition-intent.json
        if [ -s "$transition_intent" ]; then
          target=$(${pkgs.jq}/bin/jq -er '.target | select(type == "number" and . >= 0 and floor == .)' "$transition_intent")
          intent_entry=$(${pkgs.jq}/bin/jq -er '.entry_id | select(type == "string" and length > 0)' "$transition_intent")
          recorded_entry=$(${pkgs.jq}/bin/jq -er \
            --argjson target "$target" \
            '.generations[] | select(.number == $target) | .uki_path' \
            "$image_state")
          recorded_entry=''${recorded_entry##*/}
          recorded_stable=$(stable_entry_id "$recorded_entry")
          intent_stable=$(stable_entry_id "$intent_entry")
          if [ "$recorded_stable" != "$intent_stable" ]; then
            echo "aos-firstboot-reeval: image transition intent disagrees with authenticated generation $target" >&2
            exit 1
          fi
          # Authentication makes it safe to discard the selection journal,
          # but only the delayed boot-commit service may complete the image
          # transition. In particular, preserve a failed candidate as pending
          # after automatic fallback so boot commit restores the known-good
          # firmware default after host configuration has activated.
          state_update='.default = $running'
          ${pkgs.jq}/bin/jq --argjson running "$running" "$state_update" \
            "$image_state" > "''${image_state}.new"
          ${pkgs.coreutils}/bin/sync "''${image_state}.new"
          mv "''${image_state}.new" "$image_state"
          ${pkgs.coreutils}/bin/sync /var/lib/profiles/image
          rm -f "$transition_intent"
          ${pkgs.coreutils}/bin/sync /var/lib/profiles/image
        fi

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
        set -eu
        if [ ! -e "${cfg.hostNix}" ]; then
          if ! ${pkgs.aos}/bin/aos metadata restore-runtime \
            --state-dir ${provisioningStateDir}; then
            echo "aos-eval: cached host input is invalid; retaining the active generation" >&2
            exit 1
          fi
        fi

        # A missing operator input is legitimate only when no operator-backed
        # generation has ever been committed. If fresh metadata and the
        # authenticated cache are both absent after a platform/signed
        # generation, fail closed instead of evaluating `{}` and silently
        # erasing the host's policy.
        if [ ! -e "${cfg.hostNix}" ] && [ -s /var/lib/profiles/system/state.json ]; then
          current=$(${pkgs.jq}/bin/jq -er '.current' /var/lib/profiles/system/state.json)
          # The seeded image state deliberately has no config generation yet.
          # Its first stage-2 transaction must be allowed to evaluate the
          # authenticated image-default empty module and create gen-1.
          if [ "$current" -eq 0 ] && ${pkgs.jq}/bin/jq -e '.generations == []' \
            /var/lib/profiles/system/state.json >/dev/null; then
            :
          else
            manifest="/var/lib/profiles/system/gen-$current/manifest.json"
            [ -s "$manifest" ] || {
              echo "aos-eval: current generation has no retained host provenance; retaining it" >&2
              exit 1
            }
            trust=$(${pkgs.jq}/bin/jq -er '.inputs.host_nix.trust_mode' "$manifest")
            case "$trust" in
              image|image-default) ;;
              *)
                echo "aos-eval: operator-backed host input is unavailable; retaining generation $current" >&2
                exit 1
                ;;
            esac
          fi
        fi
      '';
    };

    systemd.services.aos-image-measurement-index = lib.mkIf config.aos.boot.secureBoot.measuredBoot.enable {
      description = "Import authenticated UKI PCR 11 measurement metadata";
      wantedBy = ["multi-user.target"];
      # aos-seed-profiles is an initrd-only unit and disappears at
      # switch-root. Stage 2 consumes the durable state that it wrote under
      # /var, so requiring that vanished unit would drop this job and, through
      # aos-eval's Requires= edge, silently skip host activation.
      requires = ["local-fs.target" "systemd-tmpfiles-setup.service"];
      after = ["local-fs.target" "systemd-tmpfiles-setup.service"];
      before = ["aos-eval.service" "multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        state=/var/lib/profiles/image/state.json
        if ! ${pkgs.util-linux}/bin/mountpoint -q /boot; then
          mkdir -p /boot
          ${pkgs.util-linux}/bin/mount -t vfat \
            -o ro,noatime,fmask=0077,dmask=0077 \
            ${lib.escapeShellArg config.aos.filesystems.espDevice} /boot
        fi
        running=$(${pkgs.jq}/bin/jq -er '.running' "$state")
        entry=$(${pkgs.jq}/bin/jq -er --argjson running "$running" \
          '.generations[] | select(.number == $running) | .uki_path' "$state")
        case "$entry" in
          EFI/Linux/*.efi) ;;
          *)
            echo "aos-image-measurement-index: unsafe recorded UKI path $entry" >&2
            exit 1
            ;;
        esac
        recorded_uki="/boot/$entry"
        uki="$recorded_uki"
        if [ ! -f "$uki" ]; then
          uki_name=''${entry#EFI/Linux/}
          uki_stem=''${uki_name%.efi}
          case "$uki_stem" in
            *+*)
              recorded_tries=''${uki_stem##*+}
              stable_stem=''${uki_stem%+*}
              case "$recorded_tries" in
                ""|*[!0-9]*)
                  echo "aos-image-measurement-index: invalid terminal boot count in $entry" >&2
                  exit 1
                  ;;
              esac
              ;;
            *) stable_stem=$uki_stem ;;
          esac
          found=
          for candidate in \
            "/boot/EFI/Linux/''${stable_stem}.efi" \
            "/boot/EFI/Linux/''${stable_stem}"+*.efi; do
            [ -f "$candidate" ] || continue
            if [ -n "$found" ]; then
              echo "aos-image-measurement-index: ambiguous live UKI for $entry" >&2
              exit 1
            fi
            found=$candidate
          done
          if [ -z "$found" ]; then
            echo "aos-image-measurement-index: live UKI is missing for $entry" >&2
            exit 1
          fi
          uki=$found
        fi
        measurement="$recorded_uki.measurement"
        signature="$measurement.sig"
        public_key=/run/systemd/tpm2-pcr-public-key.pem
        require_file() {
          if [ ! -f "$1" ]; then
            echo "aos-image-measurement-index: required file is missing: $1" >&2
            exit 1
          fi
        }
        registry=$(${pkgs.jq}/bin/jq -er --argjson running "$running" \
          '.generations[] | select(.number == $running) | .registry' "$state")
        recorded=$(${pkgs.jq}/bin/jq -r --argjson running "$running" \
          '[.generations[] | select(.number == $running) | .expected_pcr11][0] // ""' \
          "$state")
        if [ "$registry" != seed ]; then
          # Registry-installed generations already carry the value from their
          # independently signed release catalog. Their UKI artifact was
          # checked against that value before it was staged.
          test -n "$recorded"
          exit 0
        fi
        require_file "$uki"
        require_file "$measurement"
        require_file "$signature"
        require_file "$public_key"
        ${pkgs.openssl}/bin/openssl dgst -sha256 -verify "$public_key" \
          -signature "$signature" "$measurement" >/dev/null

        schema=
        measured_uki=
        expected=
        lines=0
        while IFS= read -r line; do
          lines=$((lines + 1))
          case "$lines:$line" in
            1:aos.uki-measurement/v1) schema=$line ;;
            2:uki_sha256=*) measured_uki=''${line#*=} ;;
            3:expected_pcr11=sha256:*) expected=''${line#*=} ;;
            *)
              echo "aos-image-measurement-index: malformed measurement metadata" >&2
              exit 1
              ;;
          esac
        done < "$measurement"
        [ "$lines" -eq 3 ] && [ "$schema" = aos.uki-measurement/v1 ]
        case "$measured_uki" in
          *[!0-9a-f]*|"") exit 1 ;;
        esac
        [ "''${#measured_uki}" -eq 64 ]
        case "$expected" in
          sha256:*) expected_hex=''${expected#sha256:} ;;
          *) exit 1 ;;
        esac
        case "$expected_hex" in
          *[!0-9a-f]*|"") exit 1 ;;
        esac
        [ "''${#expected_hex}" -eq 64 ]
        actual_uki=$(${pkgs.openssl}/bin/openssl dgst -sha256 -r "$uki")
        actual_uki=''${actual_uki%% *}
        [ "$actual_uki" = "$measured_uki" ] || {
          echo "aos-image-measurement-index: measurement metadata belongs to a different UKI" >&2
          exit 1
        }

        if [ -n "$recorded" ]; then
          [ "$recorded" = "$expected" ] || {
            echo "aos-image-measurement-index: catalog and signed UKI PCR 11 disagree" >&2
            exit 1
          }
          exit 0
        fi
        ${pkgs.jq}/bin/jq --argjson running "$running" --arg expected "$expected" \
          '(.generations[] | select(.number == $running)).expected_pcr11 = $expected' \
          "$state" > "$state.new"
        ${pkgs.coreutils}/bin/sync "$state.new"
        mv "$state.new" "$state"
        ${pkgs.coreutils}/bin/sync "$(dirname "$state")"
      '';
    };

    systemd.services.aos-eval = {
      description = "Evaluate host configuration to a converged manifest";
      environment.XDG_CACHE_HOME = "/var/cache/aos/nix-eval";
      wantedBy = ["multi-user.target"];
      # Quote generations only after systemd has advanced PCR 11 to its stable
      # runtime (`ready`) phase. On non-UKI or non-TPM boots the phase unit's
      # conditions make this a clean no-op.
      wants = ["network-online.target"];
      requires =
        [
          "aos-credential-recovery.service"
          "aos-host-config-restore.service"
          "aos-firstboot-reeval.service"
          "aos-nix-db.service"
        ]
        ++ lib.optional config.aos.boot.secureBoot.measuredBoot.enable "systemd-pcrphase.service"
        ++ lib.optional config.aos.boot.secureBoot.measuredBoot.enable "aos-image-measurement-index.service"
        ++ packageSeedReadinessUnits;
      after =
        [
          "network-online.target"
          "systemd-pcrphase.service"
          "nix-overlay-setup.service"
          "aos-config-seed.service"
          "aos-credential-recovery.service"
          "aos-seed-profiles.service"
          "aos-host-config-restore.service"
          "aos-nix-db.service"
        ]
        ++ lib.optional config.aos.boot.secureBoot.measuredBoot.enable "aos-image-measurement-index.service"
        ++ packageSeedReadinessUnits;
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
        CacheDirectory = "aos/nix-eval";
        CacheDirectoryMode = "0700";
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
        ReadWritePaths = ["/nix" "/run/aos" "/run/aos-eval" "/var/cache/aos/nix-eval"];
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
        # Invalidate every prior attempt's runtime evidence before any
        # operation which can fail.  `After=`/`Wants=` intentionally keeps a
        # failed evaluation non-fatal to boot, so downstream path conditions
        # must never be satisfiable by a same-boot stale manifest or graph.
        rm -f "${cfg.manifest}" /run/aos/graph.json
        config_state=/var/lib/profiles/system/state.json
        if [ -e /run/aos/image-reeval-required ] \
          && ${pkgs.jq}/bin/jq -e \
            '(.current > 0) and (.current as $current | any(.generations[]; .number == $current))' \
            "$config_state" >/dev/null; then
          # Rebind the exact active configuration intent to the image that
          # actually booted. Persistent platform metadata may still contain
          # the machine's original provisioning input, so it cannot be used as
          # the authority for an image transition after runtime config changes.
          # Generation zero has no retained input and follows the normal
          # provisioning path below on an image's initial seed boot.
          ${pkgs.aos}/bin/apm __eval-retained \
            --out "${cfg.manifest}" \
            --eval-root /run/aos-eval || exit 1
          exit 0
        fi
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
      description = "Commit a successful image transition";
      wantedBy = ["multi-user.target"];
      after = [
        "aos-firstboot-reeval.service"
        "aos-graph-compile.service"
        "aos-activate.service"
        "aos-config.target"
      ];
      requires = ["aos-graph-compile.service"];
      before = ["multi-user.target"];
      unitConfig.ConditionPathExists = [
        "/run/aos/image-reeval-required"
        # Direct-kernel development and fleet boots can evaluate host policy,
        # but they have no firmware-selected UKI or ESP to bless.
        "/sys/firmware/efi"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        if ! ${pkgs.util-linux}/bin/mountpoint -q /boot; then
          mkdir -p /boot
          ${pkgs.util-linux}/bin/mount -t vfat \
            -o ro,noatime,fmask=0077,dmask=0077 \
            ${lib.escapeShellArg config.aos.filesystems.espDevice} /boot
        fi
        boot_writable=false
        restore_boot_read_only() {
          if [ "$boot_writable" = true ]; then
            ${pkgs.util-linux}/bin/mount -o remount,ro /boot
          fi
        }
        trap restore_boot_read_only EXIT

        expected_esp=$(${pkgs.coreutils}/bin/readlink -f ${lib.escapeShellArg config.aos.filesystems.espDevice})
        mounted_esp=$(${pkgs.util-linux}/bin/findmnt -n -o SOURCE --target /boot)
        mounted_esp=$(${pkgs.coreutils}/bin/readlink -f "$mounted_esp")
        mounted_fstype=$(${pkgs.util-linux}/bin/findmnt -n -o FSTYPE --target /boot)
        mounted_root=$(${pkgs.util-linux}/bin/findmnt -n -o FSROOT --target /boot)
        if [ "$mounted_fstype" != vfat ] || [ "$mounted_root" != / ]; then
          echo "aos-image-boot-commit: /boot must be the root of a vfat ESP" >&2
          exit 1
        fi
        if [ ! -b "$expected_esp" ] || [ ! -b "$mounted_esp" ]; then
          echo "aos-image-boot-commit: ESP source paths must be block devices" >&2
          exit 1
        fi
        if [ "$mounted_esp" != "$expected_esp" ]; then
          echo "aos-image-boot-commit: /boot is mounted from $mounted_esp, expected $expected_esp" >&2
          exit 1
        fi

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
        manifest_hash=$(${pkgs.jq}/bin/jq -er \
          '.current as $current | .generations[] | select(.number == $current) | .manifest_hash' \
          /var/lib/profiles/system/state.json)
        proof="/var/lib/profiles/system/gen-$current/activation.json"
        attestation="/var/lib/profiles/system/gen-$current/gen-attestation.json"
        if ! ${pkgs.jq}/bin/jq -e \
          --argjson current "$current" --arg hash "$manifest_hash" \
          '.schema == "aos.config-activation/v1"
           and .generation == $current
           and .generation_id == $hash
           and (.status == "complete" or .status == "degraded")
           and (.activation_exit == 0 or .activation_exit == 5 or .activation_exit == 6)' \
          "$proof" >/dev/null; then
          echo "aos-image-boot-commit: configuration activation proof is incomplete" >&2
          exit 1
        fi
        if ! ${pkgs.jq}/bin/jq -e \
          --arg hash "$manifest_hash" \
          '.schema == "aos.gen-attestation/v1"
           and .generation_id == $hash
           and .manifest_hash == $hash
           and .eval_mode == "pure-eval"' \
          "$attestation" >/dev/null; then
          echo "aos-image-boot-commit: generation attestation is incomplete" >&2
          exit 1
        fi
        ${lib.optionalString config.aos.boot.secureBoot.measuredBoot.enable ''
          if ! ${pkgs.jq}/bin/jq -e \
            '.quote_status == "quoted" and (.quote | type == "string" and length > 0)' \
            "$attestation" >/dev/null; then
            echo "aos-image-boot-commit: measured boot requires a quoted generation attestation" >&2
            exit 1
          fi
          expected_pcr11=$(${pkgs.jq}/bin/jq -r \
            --argjson running "$running" \
            '[.generations[] | select(.number == $running) | .expected_pcr11][0] // ""' \
            "$state")
          quote_dir="/var/lib/profiles/system/gen-$current/gen-attestation-quote"
          if [ -n "$expected_pcr11" ]; then
            ${pkgs.aos}/bin/apm attest __verify-boot-commit \
              --generation-attestation "$attestation" \
              --quote-dir "$quote_dir" \
              --expected-pcr11 "$expected_pcr11"
          else
            ${pkgs.aos}/bin/apm attest __verify-boot-commit \
              --generation-attestation "$attestation" \
              --quote-dir "$quote_dir"
          fi
        ''}
        if [ "$parent" != "$running" ]; then
          echo "aos-image-boot-commit: configuration has not rebound to running image $running" >&2
          exit 1
        fi
        entry=$(${pkgs.jq}/bin/jq -er \
          --argjson running "$running" \
          '.generations[] | select(.number == $running) | .uki_path' "$state")
        case "$entry" in
          EFI/Linux/*.efi) ;;
          *)
            echo "aos-image-boot-commit: unsafe recorded UKI path $entry" >&2
            exit 1
            ;;
        esac
        uki_name=''${entry#EFI/Linux/}
        case "$uki_name" in
          */*|"")
            echo "aos-image-boot-commit: unsafe nested UKI path $entry" >&2
            exit 1
            ;;
        esac

        case "$uki_name" in
          *.efi) ;;
          *)
            echo "aos-image-boot-commit: recorded UKI does not end in .efi: $entry" >&2
            exit 1
            ;;
        esac
        uki_stem=''${uki_name%.efi}
        case "$uki_stem" in
          *+*)
            recorded_tries=''${uki_stem##*+}
            stable_stem=''${uki_stem%+*}
            case "$recorded_tries" in
              ""|*[!0-9]*)
                echo "aos-image-boot-commit: invalid terminal boot count in $entry" >&2
                exit 1
                ;;
            esac
            if [ "$recorded_tries" -eq 0 ]; then
              echo "aos-image-boot-commit: exhausted UKI cannot identify a generation: $entry" >&2
              exit 1
            fi
            ;;
          *) stable_stem=$uki_stem ;;
        esac
        stable="EFI/Linux/''${stable_stem}.efi"
        stable_path="/boot/$stable"

        # Bless only a pending candidate that actually became the running
        # image. When sd-boot has already fallen back, the running known-good
        # entry is normally uncounted and blessing would fail; in that
        # arm we merely restore it as the durable default below. A stable file
        # also means an earlier attempt already completed the rename, making
        # this step idempotent across a crash before state publication.
        if [ "$pending" -eq "$running" ]; then
          ${pkgs.util-linux}/bin/mount -o remount,rw /boot
          boot_writable=true
          live_counted=false
          for candidate in "/boot/EFI/Linux/''${stable_stem}"+*.efi; do
            [ -e "$candidate" ] || continue
            candidate_name=''${candidate##*/}
            candidate_count=''${candidate_name%.efi}
            candidate_count=''${candidate_count##*+}
            tries=''${candidate_count%%-*}
            case "$tries" in
              ""|*[!0-9]*) continue ;;
            esac
            case "$candidate_count" in
              *-*)
                completed=''${candidate_count#*-}
                case "$completed" in
                  ""|*[!0-9]*|*-*) continue ;;
                esac
                ;;
            esac
            if [ "$tries" -gt 0 ]; then
              live_counted=true
              break
            fi
          done
          if [ "$live_counted" = true ]; then
            ${pkgs.systemd}/lib/systemd/systemd-bless-boot --path=/boot good
          elif [ ! -e "$stable_path" ]; then
            echo "aos-image-boot-commit: neither a live counted nor stable UKI exists for $entry" >&2
            exit 1
          fi
        fi

        # A failed pending candidate may already have fallen back to `running`.
        # Resolve the successful entry's stable name after boot-count renaming.
        if [ "$boot_writable" != true ]; then
          ${pkgs.util-linux}/bin/mount -o remount,rw /boot
          boot_writable=true
        fi
        ${pkgs.systemd}/bin/bootctl set-default "''${stable##*/}"

        # Restore the ESP's steady-state protection before publishing the
        # transition as complete. If this remount fails, the durable pending
        # state and runtime marker remain and the next boot retries the
        # idempotent blessing/reconciliation path.
        ${pkgs.util-linux}/bin/mount -o remount,ro /boot
        boot_writable=false

        ${pkgs.jq}/bin/jq --argjson running "$running" \
          '.default = $running | .pending = null' "$state" > "''${state}.new"
        ${pkgs.coreutils}/bin/sync "''${state}.new"
        mv "''${state}.new" "$state"
        ${pkgs.coreutils}/bin/sync "$(dirname "$state")"
        # A power loss can leave the pre-selection intent after firmware and
        # state already agree. Successful boot assessment is the authoritative
        # reconciliation point, so clear it durably here as well as in the
        # normal userspace selection path.
        rm -f /var/lib/profiles/image/.transition-intent.json
        ${pkgs.coreutils}/bin/sync /var/lib/profiles/image
        rm -f /run/aos/image-reeval-required
        trap - EXIT
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
