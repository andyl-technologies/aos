# Cheap classifier half of drop-one attribution for one patch. Consumes the
# expensive, classification-independent `_drop-one-build.nix` (which consumes a
# 3-way variant prepared in the shared repository and, when clean, builds it)
# and assigns exactly one attribution method from its raw outcome. Because this
# derivation does not rebuild QEMU, tuning the classification is cheap.
#
# Attribution methods:
#   drop-one-source-dependency : rebase-drop conflicts -- N is required for a
#                                specific later patch's 3-way application (quoted).
#   drop-one-build-required    : N drops clean but full-minus-N fails to build,
#                                referencing symbols N implements (recorded).
#   drop-one-symbol            : N drops clean, builds, and its exported ABI
#                                symbols are present in the full binary and absent
#                                in the variant.
#   drop-one-semantic          : N drops clean, builds, exports no ABI symbol (a
#                                sim-gated behavioral patch); a live boot probe
#                                compares the full QEMU with the full-minus-N
#                                variant.
#   drop-one-composition       : the patch drops and builds, but the generic
#                                behavioral workload does not reach its effect;
#                                bind that result to its focused stock-negative
#                                microtest and retain the explicit coverage gap.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  index,
  attrPath,
  expectAbsentSymbols ? [],
  expectInternalBuildFailures ? [],
  # RTC clock mode for the behavioral sim-divergence probe (see _sim-diverge.nix).
  rtcClock ? "vm",
  dropOneRepository ?
    import ./_qemu-drop-one-repository.nix {
      inherit pkgs lib qemuPackage;
    },
  buildDrv ?
    import ./_drop-one-build.nix {
      inherit pkgs lib qemuPackage index dropOneRepository;
      attrPath = "${attrPath}.build";
    },
  # Behavioral (sim-gated, no exported ABI symbol) patches are discriminated by
  # a live variant-divergence sim probe. Only consumed when the build succeeds
  # and no symbol discriminator is supplied.
  simDiverge ?
    import ./_sim-diverge.nix {
      inherit pkgs lib index qemuPackage buildDrv rtcClock;
      attrPath = "${attrPath}.simDiverge";
    },
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  droppedPatch = builtins.elemAt series.patchFiles (index - 1);
  symbolsMaterial = builtins.concatStringsSep " " expectAbsentSymbols;
  internalIdentifiersMaterial = builtins.concatStringsSep " " (
    map (evidence: evidence.identifier) expectInternalBuildFailures
  );
  internalBuildEvidenceMaterial =
    lib.concatMapStringsSep "\n" (
      evidence: "${evidence.identifier}|${evidence.path}|${evidence.fullSourceNeedle}"
    )
    expectInternalBuildFailures
    + lib.optionalString (expectInternalBuildFailures != []) "\n";
  hasSymbols = expectAbsentSymbols != [];
in
  pkgs.mkDerivation {
    pname = "crucible-drop-one-${toString index}";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.binutils
      pkgs.coreutils
      pkgs.gawk
      pkgs.git
      pkgs.grep
      pkgs.sed
      qemuPackage
    ];

    DROPPED_PATCH = droppedPatch;
    DROP_INDEX = toString index;
    EXPECT_ABSENT_SYMBOLS = symbolsMaterial;
    EXPECT_INTERNAL_IDENTIFIERS = internalIdentifiersMaterial;
    DROP_ONE_REPOSITORY = "${dropOneRepository}";
    passAsFile = ["internalBuildEvidenceMaterial"];
    inherit internalBuildEvidenceMaterial;
    BUILD_DRV = "${buildDrv}";
    FULL_QEMU = "${qemuPackage}/bin/qemu-system-x86_64";
    # Only behavioral (no-symbol) patches consult the sim-divergence probe; for
    # symbol patches this stays empty so the probe is never built.
    SIM_DIVERGE =
      if hasSymbols
      then ""
      else "${simDiverge}";

    phases = [
      {
        name = "drop-one-classify";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"
          fail() { echo "FAIL: $*" >&2; exit 1; }
          . ${./_drop-one-build-evidence.sh}

          test "$(cat "$BUILD_DRV/dropped-patch")" = "$DROPPED_PATCH" \
            || fail "build derivation names a different patch"
          outcome=$(cat "$BUILD_DRV/outcome")

          emit() {
            if [ "$outcome" != conflict ]; then
              test "$(cat "$BUILD_DRV/source-materialized")" = true \
                || fail "clean variant was not materialized from its prepared ref"
              grep -Fqx 'source_reconstruction_inventory_consumed=true' \
                "$BUILD_DRV/source-reconstruction.env" \
                || fail "clean variant did not consume the verified source inventory"
              cat "$BUILD_DRV/source-reconstruction.env" >> "$out/attribution.env"
            fi
            {
              echo PASS
              echo "check=${attrPath}"
              echo "gate=gate:patch-microtests"
              echo "dropped_patch=$DROPPED_PATCH"
              echo "drop_index=$DROP_INDEX"
              cat "$out/attribution.env"
            } > "$out/result"
          }

          case "$outcome" in
            conflict)
              test ! -e "$BUILD_DRV/source-materialized" \
                || fail "conflicting variant unexpectedly materialized a QEMU tree"
              cp "$BUILD_DRV/conflict.env" "$out/conflict.env"
              {
                echo "attribution_method=drop-one-source-dependency"
                echo "drop_conflicts=true"
                cat "$BUILD_DRV/conflict.env"
                echo "patch_is_load_bearing_for_later_series_application=true"
              } > "$out/attribution.env"
              emit
              ;;
            build-failed)
              cp "$BUILD_DRV/build.log" "$out/build.log"
              extract_drop_one_build_evidence \
                "$out/build.log" "$out/patch-specific-build-evidence" \
                "$out/build-diagnostics"
              test -s "$out/patch-specific-build-evidence" \
                || fail "build failure lacks patch-specific compiler/linker evidence"
              nm -D --defined-only "$FULL_QEMU" | gawk 'NF { print $NF }' | LC_ALL=C sort -u \
                > "$out/full-exports"
              validate_drop_one_build_evidence \
                "$out/patch-specific-build-evidence" "$out/full-exports" \
                "$EXPECT_ABSENT_SYMBOLS" "$EXPECT_INTERNAL_IDENTIFIERS" \
                || fail "build failure evidence is not an exact manifest discriminator"
              variant_ref=$(gawk -F= '$1 == "prepared_ref" { print $2 }' \
                "$BUILD_DRV/prepared-ref.env")
              test -n "$variant_ref" \
                || fail "build failure is missing its prepared variant ref"
              internal_source_definition_loss_verified=false
              while IFS='|' read -r identifier source_path full_source_needle; do
                if ! gawk -F '\t' -v expected="$identifier" \
                  '$1 == "symbol" && $2 == expected { found = 1 } END { exit !found }' \
                  "$out/patch-specific-build-evidence"; then
                  continue
                fi
                full_internal_source="$TMPDIR/full-internal-source"
                variant_internal_source="$TMPDIR/variant-internal-source"
                git --git-dir="$DROP_ONE_REPOSITORY/repo.git" \
                  show "refs/heads/patch-stack:$source_path" > "$full_internal_source" \
                  || fail "cannot read the full-stack source for $identifier"
                grep -Fq "$full_source_needle" "$full_internal_source" \
                  || fail "full stack lacks the manifest internal definition for $identifier"
                git --git-dir="$DROP_ONE_REPOSITORY/repo.git" \
                  show "$variant_ref:$source_path" > "$variant_internal_source" \
                  || fail "cannot read the full-minus-N source for $identifier"
                if grep -Fq "$full_source_needle" "$variant_internal_source"; then
                  fail "full-minus-N source still contains the internal definition for $identifier"
                fi
                internal_source_definition_loss_verified=true
              done < "$internalBuildEvidenceMaterialPath"
              gawk -F '\t' '$1 == "symbol" { print $2 }' \
                "$out/patch-specific-build-evidence" > "$out/failing-symbols"
              grep -E '^qemu_plugin_' "$out/failing-symbols" > "$out/failing-plugin-symbols" || true
              {
                echo "attribution_method=drop-one-build-required"
                echo "drop_conflicts=false"
                echo "full_minus_n_build_fails=true"
                echo "exact_manifest_build_failure_evidence=true"
                echo "internal_source_definition_loss_verified=$internal_source_definition_loss_verified"
                echo "failing_symbol_count=$(wc -l < "$out/failing-symbols" | tr -d ' ')"
                echo "build_failure_references_plugin_symbols=$(test -s "$out/failing-plugin-symbols" && echo true || echo false)"
              } > "$out/attribution.env"
              emit
              ;;
            built)
              variant="$BUILD_DRV/variant-qemu-system-x86_64"
              test -x "$variant" || fail "built outcome but no variant binary"
              nm -D --defined-only "$variant" | gawk 'NF { print $NF }' | LC_ALL=C sort -u \
                > "$out/variant-exports"
              nm -D --defined-only "$FULL_QEMU" | gawk 'NF { print $NF }' | LC_ALL=C sort -u \
                > "$out/full-exports"
              if [ -n "''${EXPECT_ABSENT_SYMBOLS:-}" ]; then
                for s in $EXPECT_ABSENT_SYMBOLS; do
                  grep -q -x "$s" "$out/full-exports" \
                    || fail "$s expected in full binary but absent"
                  if grep -q -x "$s" "$out/variant-exports"; then
                    fail "$s still exported by full-minus-$DROP_INDEX (drop did not remove the effect)"
                  fi
                done
                {
                  echo "attribution_method=drop-one-symbol"
                  echo "drop_conflicts=false"
                  echo "full_minus_n_build_succeeds=true"
                  echo "effect_symbols_present_in_full_absent_in_variant=$EXPECT_ABSENT_SYMBOLS"
                } > "$out/attribution.env"
                emit
              else
                # Sim-gated behavioral patch (no exported ABI symbol). Boot the
                # full-minus-N variant under the shared sim workload and read
                # the live divergence classification.
                cp "$SIM_DIVERGE/result" "$out/sim-diverge.result"
                cp "$SIM_DIVERGE/variant-fingerprints" "$out/variant-fingerprints" 2>/dev/null || true
                cls=$(gawk -F= '/^sim_discriminator_classification=/ { print $2 }' "$SIM_DIVERGE/result")
                rtd=$(gawk -F= '/^runs_to_diverge=/ { print $2 }' "$SIM_DIVERGE/result")
                sf=$(gawk -F= '/^semantic_form=/ { print $2 }' "$SIM_DIVERGE/result")
                case "$cls" in
                  diverges)
                    # N suppresses a nondeterminism that reappears without it:
                    # variant runs diverge while full is deterministic. Present in
                    # full, absent in the variant, at runtime (kills sibling-patch
                    # masking).
                    {
                      echo "attribution_method=drop-one-semantic"
                      echo "drop_conflicts=false"
                      echo "full_minus_n_build_succeeds=true"
                      echo "effect_is_sim_gated=true"
                      echo "semantic_form=variant-run-twice-diverges"
                      echo "variant_nondeterministic_full_deterministic=true"
                      echo "runs_to_diverge=$rtd"
                      echo "runtime_effect_proven_against_variant=true"
                    } > "$out/attribution.env"
                    ;;
                  differs)
                    # N's fixed-behavior effect is guest-observable: variant is
                    # deterministic but its fingerprint differs from full.
                    if [ -z "$sf" ]; then
                      sf=variant-differs-from-full
                    fi
                    {
                      echo "attribution_method=drop-one-semantic"
                      echo "drop_conflicts=false"
                      echo "full_minus_n_build_succeeds=true"
                      echo "effect_is_sim_gated=true"
                      echo "semantic_form=$sf"
                      echo "sim_discriminator_result=sim-diverge.result"
                      echo "runtime_effect_proven_against_variant=true"
                    } > "$out/attribution.env"
                    ;;
                  none)
                    # The generic workload does not reach N's effect
                    # (non-discriminating). Fall back to composition: LIVE
                    # drop-clean + build (this gate) + the patch's own full-series
                    # micro-test stock negative control (run by the aggregate).
                    # Flagged as a latent runtime gap (its microtest needs a
                    # runtime upgrade -- tracked separately).
                    {
                      echo "attribution_method=drop-one-composition"
                      echo "drop_conflicts=false"
                      echo "full_minus_n_build_succeeds=true"
                      echo "effect_is_sim_gated=true"
                      echo "sim_diverge_workload_non_discriminating=true"
                      echo "runtime_effect_evidence=drop-clean-plus-build-plus-microtest-stock-negative-control"
                      echo "latent_gap_microtest_needs_runtime_upgrade=true"
                    } > "$out/attribution.env"
                    ;;
                  *)
                    fail "unexpected sim-diverge classification: $cls"
                    ;;
                esac
                emit
              fi
              ;;
            *)
              fail "unknown build outcome: $outcome"
              ;;
          esac
        '';
      }
    ];
  }
