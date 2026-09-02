# lib/testing/config-materialize.nix — configuration manifest materializer integration.
#
# The eval-only core PRODUCES `config.system.build.configManifest` (an
# `aos.config-manifest/v1` document). This gate feeds a REAL server manifest to
# the REAL `apm __materialize` (crates/aos-package/src/config_eval/materialize.rs)
# and asserts the applied `/etc` tree — closing the producer↔consumer loop
# off-host, without a booted VM. It complements the unit tests (which use
# hand-written manifests) by proving the materializer handles the full,
# real-world manifest shape.
#
# Runs via `nix-build -A checks.config-materialize`.
{
  pkgs,
  lib,
}: let
  aos = import ../../. {system = pkgs.stdenv.buildPlatform.system;};

  system = aos.mkSystem {
    modules = [../../systems/server.nix];
    operatorModules = [
      {
        environment.etc."runtime-config/materialized.conf" = {
          text = "host-owned\n";
          mode = "0644";
        };
        systemd.services.runtime-config-materialized = {
          wantedBy = ["multi-user.target"];
          serviceConfig.Type = "oneshot";
          script = "printf materialized > /run/runtime-config-materialized";
        };
      }
    ];
  };

  # Exercise the same resolver-controlled `operatorModules` provenance arm
  # that the evaluator uses after authenticating host.nix. `toFile`
  # rejects string context, and the manifest's store-path strings carry it;
  # the manifest is pure data here, so discard it (the paths stay verbatim).
  manifestJson = builtins.toJSON system.config.system.build.configManifest;
  manifestFile =
    builtins.toFile "config-manifest.json"
    (builtins.unsafeDiscardStringContext manifestJson);
in
  pkgs.mkDerivation {
    pname = "config-materialize-check";
    version = "0";
    src = null;
    buildDeps = [pkgs.aos pkgs.coreutils pkgs.grep pkgs.findutils pkgs.erofs-utils];
    phases = [
      {
        name = "check";
        script = ''
          set -eu
          mkdir -p "$out"
          generation="$(${pkgs.coreutils}/bin/mktemp -d)/gen-1"
          mkdir -p "$generation"

          fail() {
            echo "FAIL: $1" >&2
            exit 1
          }

          echo "==> materializing the server configManifest" | tee "$out/result"
          ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __materialize \
            --manifest ${manifestFile} \
            --generation-dir "$generation" \
            --mkfs-erofs ${pkgs.erofs-utils}/bin/mkfs.erofs \
            --fsck-erofs ${pkgs.erofs-utils}/bin/fsck.erofs

          lower="$generation/config-lower"
          etc_root="$lower/etc-tree"
          [ -f "$lower/etc.erofs" ] || fail "content-addressed EROFS lower was not published"
          [ -f "$lower/metadata.json" ] || fail "lower integrity metadata was not published"
          ${pkgs.erofs-utils}/bin/fsck.erofs "$lower/etc.erofs" >/dev/null \
            || fail "published EROFS image failed fsck"

          # Host-owned text lands as a real file. Image-owned base artifacts
          # stay in the image lower and must not be duplicated in this lower.
          runtime_file="$etc_root/runtime-config/materialized.conf"
          [ -f "$runtime_file" ] || fail "host-owned text entry not materialized"
          ${pkgs.grep}/bin/grep -qx 'host-owned' "$runtime_file" \
            || fail "host-owned text content missing"
          [ ! -e "$etc_root/apm/registries.d/andyl.toml" ] \
            || fail "image-owned registry was duplicated into the runtime lower"

          # A relative install `symlink` entry (the systemd .wants farm).
          units="$etc_root/systemd/system"
          [ -d "$units" ] || fail "systemd/system not materialized"
          wants_link="$(${pkgs.findutils}/bin/find "$units" -type l -path '*.wants/*' | ${pkgs.coreutils}/bin/head -n1)"
          [ -n "$wants_link" ] || fail "no .wants install symlink materialized"
          case "$(${pkgs.coreutils}/bin/readlink "$wants_link")" in
            ../*) ;;
            *) fail "install symlink target is not the expected relative ../ form" ;;
          esac

          # Job scripts are materialized and their placeholders are rewritten:
          # no `#aos-jobscript:` token survives in any unit body, and at least
          # one unit references a materialized /etc/aos-job-scripts/ path.
          [ -d "$etc_root/aos-job-scripts" ] || fail "aos-job-scripts dir not materialized"
          if ${pkgs.grep}/bin/grep -rq '#aos-jobscript:' "$units"; then
            fail "an unresolved #aos-jobscript: placeholder survived in a unit body"
          fi
          ${pkgs.grep}/bin/grep -rq '/etc/aos-job-scripts/' "$units" \
            || fail "no unit body references a materialized job-script path"

          # A materialized job script is executable (mode 0755).
          js="$(${pkgs.findutils}/bin/find "$etc_root/aos-job-scripts" -type f | ${pkgs.coreutils}/bin/head -n1)"
          [ -n "$js" ] || fail "no job script file materialized"
          [ -x "$js" ] || fail "materialized job script is not executable"

          # A byte-identical retry validates and reuses the immutable artifact.
          before="$(${pkgs.coreutils}/bin/sha256sum "$lower/etc.erofs")"
          ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __materialize \
            --manifest ${manifestFile} \
            --generation-dir "$generation" \
            --mkfs-erofs ${pkgs.erofs-utils}/bin/mkfs.erofs \
            --fsck-erofs ${pkgs.erofs-utils}/bin/fsck.erofs
          after="$(${pkgs.coreutils}/bin/sha256sum "$lower/etc.erofs")"
          [ "$before" = "$after" ] || fail "idempotent reuse changed the EROFS lower"

          # Tampering is detected before an existing generation can be reused.
          ${pkgs.coreutils}/bin/printf x >> "$lower/etc.erofs"
          if ${pkgs.aos.packageRuntime}/bin/aos-package-runtime __materialize \
            --manifest ${manifestFile} \
            --generation-dir "$generation" \
            --mkfs-erofs ${pkgs.erofs-utils}/bin/mkfs.erofs \
            --fsck-erofs ${pkgs.erofs-utils}/bin/fsck.erofs; then
            fail "tampered EROFS lower was accepted"
          fi

          echo "  text entry + mode: OK" | tee -a "$out/result"
          echo "  relative install symlink: OK" | tee -a "$out/result"
          echo "  job-script materialization + placeholder rewrite: OK" | tee -a "$out/result"
          echo "  atomic EROFS publication + reuse/tamper validation: OK" | tee -a "$out/result"
        '';
      }
    ];
  }
