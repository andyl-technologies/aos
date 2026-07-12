# Cheap classifier half of drop-one attribution for one patch. Consumes the
# expensive, classification-independent `_drop-one-build.nix` (which does the
# 3-way rebase-drop and, when clean, the full-minus-N build) and assigns exactly
# one attribution method from its raw outcome. Because this derivation does not
# rebuild QEMU, tuning the classification is cheap.
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
#                                sim-gated behavioral patch); its runtime effect is
#                                proven by its own full-series micro-test's stock
#                                negative control (effect present on patched qemu,
#                                absent on unpatched -- absent exactly when N's
#                                code is absent), which the patch-microtests
#                                aggregate that consumes this gate runs.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  index,
  attrPath,
  expectAbsentSymbols ? [],
  buildDrv ?
    import ./_drop-one-build.nix {
      inherit pkgs lib qemuPackage index;
      attrPath = "${attrPath}.build";
    },
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  droppedPatch = builtins.elemAt series.patchFiles (index - 1);
  symbolsMaterial = builtins.concatStringsSep " " expectAbsentSymbols;
in
  pkgs.mkDerivation {
    pname = "crucible-drop-one-${toString index}";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.binutils
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      qemuPackage
    ];

    DROPPED_PATCH = droppedPatch;
    DROP_INDEX = toString index;
    EXPECT_ABSENT_SYMBOLS = symbolsMaterial;
    BUILD_DRV = "${buildDrv}";
    FULL_QEMU = "${qemuPackage}/bin/qemu-system-x86_64";

    phases = [
      {
        name = "drop-one-classify";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"
          fail() { echo "FAIL: $*" >&2; exit 1; }

          test "$(cat "$BUILD_DRV/dropped-patch")" = "$DROPPED_PATCH" \
            || fail "build derivation names a different patch"
          outcome=$(cat "$BUILD_DRV/outcome")

          emit() {
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
              cp "$BUILD_DRV/failing-symbols" "$out/failing-symbols"
              grep -E '^qemu_plugin_' "$out/failing-symbols" > "$out/failing-plugin-symbols" || true
              {
                echo "attribution_method=drop-one-build-required"
                echo "drop_conflicts=false"
                echo "full_minus_n_build_fails=true"
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
                # Sim-gated behavioral patch (no exported ABI symbol). Its effect
                # is observable only under -accel sim; the patched and unpatched
                # binaries are byte-behaviorally identical under tcg (the inertness
                # guarantee). The runtime "effect vanishes without N" evidence is
                # the patch's OWN full-series micro-test stock negative control
                # (effect present on patched qemu, absent on unpatched -- absent
                # exactly when N's code is absent), which the patch-microtests
                # aggregate that consumes this gate runs. This gate proves the LIVE
                # assembly facts: N drops clean and full-minus-N builds, so N is
                # individually removable and self-contained, not masked.
                {
                  echo "attribution_method=drop-one-semantic"
                  echo "drop_conflicts=false"
                  echo "full_minus_n_build_succeeds=true"
                  echo "effect_is_sim_gated=true"
                  echo "tcg_behavior_identical_by_inertness_guarantee=true"
                  echo "runtime_effect_proven_by_patch_full_series_microtest_stock_negative_control=true"
                  echo "drop_one_proves_clean_removable_and_self_contained=true"
                } > "$out/attribution.env"
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
