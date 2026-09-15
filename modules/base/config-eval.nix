##! modules/base/config-eval.nix — on-host configuration evaluation
##!
##! Authors `aos-eval.service`: the stage-2 systemd unit that drives the
##! resolve↔eval fixpoint (`aos-package-runtime __eval`) over the in-image base library, the
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
    aos.packageRuntime.configurationEvaluation = {
      enable = true;
      hostNix = cfg.hostNix;
      baseLib =
        if cfg.baseLib == null
        then "/aos-toplevel/base-lib"
        else toString cfg.baseLib;
      moduleAbi = cfg.moduleAbi;
      desired = cfg.desired;
      manifest = cfg.manifest;
      evalRoot = "/run/aos-eval";
      provisioningState = provisioningStateDir;
      imageVersion = config.aos.system.version;
      requireAttestationQuote = config.aos.boot.secureBoot.measuredBoot.enable;
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

    systemd.services.aos-image-measurement-index = lib.mkIf config.aos.boot.secureBoot.measuredBoot.enable {
      description = "Import authenticated UKI PCR 11 measurement metadata";
      wantedBy = ["multi-user.target"];
      # aos-seed-profiles is an initrd-only unit and disappears at
      # switch-root. Stage 2 consumes the durable state that it wrote under
      # /var, so requiring that vanished unit would drop this job and, through
      # aos-eval's Requires= edge, silently skip host activation.
      requires = ["aos-mount-esp.service" "local-fs.target" "systemd-tmpfiles-setup.service"];
      after = ["aos-mount-esp.service" "local-fs.target" "systemd-tmpfiles-setup.service"];
      before = ["aos-eval.service" "multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        set -euo pipefail
        state=/var/lib/profiles/image/state.json
        ${pkgs.util-linux}/bin/mountpoint -q /boot || {
          echo "aos-image-measurement-index: booted ESP is not mounted" >&2
          exit 1
        }
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



  };
}
