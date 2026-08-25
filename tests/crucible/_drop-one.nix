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
#   drop-one-binary            : the focused boot does not reach N, but removing
#                                N changes the same-builder emulator executable.
#   drop-one-test-fixture      : N changes only an explicitly catalogued QEMU
#                                test fixture; the shipped executable stays byte
#                                identical while the exact fixture material is
#                                present in full and absent in full-minus-N.
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
  expectTestFixtureEvidence ? [],
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
  # A same-builder assembly reference derived by dropping the test-only 0081
  # patch. That patch changes only tests/tcg material, so this avoids comparing
  # variant ELFs against the differently packaged production derivation.
  binaryReferenceBuildDrv ?
    import ./_drop-one-build.nix {
      inherit pkgs lib qemuPackage dropOneRepository;
      index = 78;
      attrPath = "${attrPath}.binaryReference";
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
  testFixtureEvidenceMaterial =
    lib.concatMapStringsSep "\n" (
      evidence: "${evidence.path}|${evidence.fullSourceNeedle}"
    )
    expectTestFixtureEvidence
    + lib.optionalString (expectTestFixtureEvidence != []) "\n";
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
    passAsFile = [
      "internalBuildEvidenceMaterial"
      "testFixtureEvidenceMaterial"
    ];
    inherit internalBuildEvidenceMaterial testFixtureEvidenceMaterial;
    BUILD_DRV = "${buildDrv}";
    BINARY_REFERENCE_BUILD_DRV = "${binaryReferenceBuildDrv}";
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
                    # The generic workload is deliberately small and does not
                    # reach every late control-plane effect. Prove that N is
                    # nevertheless load-bearing at the shipped-artifact boundary.
                    # Byte-identical binaries are accepted only for the explicit
                    # test-fixture manifest below, whose exact material is checked
                    # against both source graphs.
                    test "$(cat "$BINARY_REFERENCE_BUILD_DRV/outcome")" = built \
                      || fail "assembly-reference variant did not build"
                    test "$(cat "$BINARY_REFERENCE_BUILD_DRV/dropped-patch")" = \
                      0081-crucible-deferred-result-evidence-test.patch \
                      || fail "assembly-reference variant dropped the wrong patch"
                    reference="$BINARY_REFERENCE_BUILD_DRV/variant-qemu-system-x86_64"
                    test -x "$reference" \
                      || fail "assembly-reference QEMU is missing"
                    reference_sha256=$(sha256sum "$reference" | gawk '{ print $1 }')
                    variant_sha256=$(sha256sum "$variant" | gawk '{ print $1 }')
                    if [ "$reference_sha256" != "$variant_sha256" ]; then
                      {
                        echo "attribution_method=drop-one-binary"
                        echo "drop_conflicts=false"
                        echo "full_minus_n_build_succeeds=true"
                        echo "sim_diverge_workload_non_discriminating=true"
                        echo "assembly_reference_patch=0081-crucible-deferred-result-evidence-test.patch"
                        echo "assembly_reference_executable_sha256=$reference_sha256"
                        echo "variant_executable_sha256=$variant_sha256"
                        echo "same_builder_executable_changes_without_patch=true"
                      } > "$out/attribution.env"
                    else
                      test -s "$testFixtureEvidenceMaterialPath" \
                        || fail "byte-identical full-minus-$DROP_INDEX lacks explicit test-fixture evidence"
                      variant_ref=$(gawk -F= '$1 == "prepared_ref" { print $2 }' \
                        "$BUILD_DRV/prepared-ref.env")
                      test -n "$variant_ref" \
                        || fail "test-fixture variant is missing its prepared ref"
                      fixture_count=0
                      : > "$TMPDIR/expected-fixture-paths"
                      while IFS='|' read -r source_path full_source_needle; do
                        test -n "$source_path" \
                          || fail "test-fixture evidence has an empty source path"
                        test -n "$full_source_needle" \
                          || fail "test-fixture evidence has an empty source needle"
                        full_fixture_source="$TMPDIR/full-fixture-source"
                        variant_fixture_source="$TMPDIR/variant-fixture-source"
                        git --git-dir="$DROP_ONE_REPOSITORY/repo.git" \
                          show "refs/heads/patch-stack:$source_path" \
                          > "$full_fixture_source" \
                          || fail "cannot read full test fixture $source_path"
                        grep -Fq "$full_source_needle" "$full_fixture_source" \
                          || fail "full stack lacks catalogued test-fixture material in $source_path"
                        git --git-dir="$DROP_ONE_REPOSITORY/repo.git" \
                          show "$variant_ref:$source_path" \
                          > "$variant_fixture_source" \
                          || fail "cannot read full-minus-N test fixture $source_path"
                        if grep -Fq "$full_source_needle" "$variant_fixture_source"; then
                          fail "full-minus-$DROP_INDEX retains catalogued test-fixture material in $source_path"
                        fi
                        printf '%s\n' "$source_path" >> "$TMPDIR/expected-fixture-paths"
                        fixture_count=$((fixture_count + 1))
                      done < "$testFixtureEvidenceMaterialPath"
                      test "$fixture_count" -gt 0
                      LC_ALL=C sort -u "$TMPDIR/expected-fixture-paths" \
                        > "$TMPDIR/expected-fixture-paths.sorted"
                      git --git-dir="$DROP_ONE_REPOSITORY/repo.git" diff --name-only \
                        "$variant_ref" refs/heads/patch-stack \
                        | LC_ALL=C sort -u > "$TMPDIR/actual-fixture-paths.sorted"
                      cmp "$TMPDIR/expected-fixture-paths.sorted" \
                        "$TMPDIR/actual-fixture-paths.sorted" \
                        || fail "byte-identical test-fixture drop changes uncatalogued source paths"
                      {
                        echo "attribution_method=drop-one-test-fixture"
                        echo "drop_conflicts=false"
                        echo "full_minus_n_build_succeeds=true"
                        echo "sim_diverge_workload_non_discriminating=true"
                        echo "assembly_reference_patch=0081-crucible-deferred-result-evidence-test.patch"
                        echo "assembly_reference_executable_sha256=$reference_sha256"
                        echo "variant_executable_sha256=$variant_sha256"
                        echo "same_builder_executable_byte_identical=true"
                        echo "exact_test_fixture_source_loss_verified=true"
                        echo "test_fixture_evidence_count=$fixture_count"
                      } > "$out/attribution.env"
                    fi
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
