# Drop-one attribution aggregate.
#
# A single shared repository removes every carried patch N with a 3-way `git
# rebase --onto`. Per-patch derivations then observe the prepared result LIVE
# and build only clean variants. Nothing about the clean/conflict split or the
# build-fail/succeed split is hardcoded, so a future reordering/decoupling of the
# series automatically migrates patches between branches. Each patch resolves
# to exactly one attribution method:
#
#   drop-one-source-dependency : N cannot be removed without breaking a later
#                                patch's 3-way application (the tightly-coupled
#                                majority of this facade-first series).
#   drop-one-build-required    : N drops clean but full-minus-N fails to build
#                                because earlier code references N's symbols.
#   drop-one-symbol            : N drops clean, full-minus-N builds, and N's
#                                exported ABI symbols are present in the full
#                                binary and absent in the variant.
#   drop-one-semantic          : N drops clean, full-minus-N builds and exports
#                                no ABI symbol; a sim-mode runtime probe shows N's
#                                effect present in full and absent in the variant.
#   drop-one-binary            : the focused runtime probe is non-discriminating,
#                                but the same-builder emulator executable changes.
#   drop-one-test-fixture      : an explicitly catalogued QEMU test-only patch
#                                changes exact fixture material while leaving the
#                                shipped executable byte-identical.
#   drop-one-composition       : Legacy fail-closed classification for a patch
#                                whose runtime effect was not reached. The
#                                aggregate rejects this result.
#
# This is layered on top of the source-provenance attribution gate; together they
# give every patch runtime-or-assembly load-bearing evidence, no bare needle.
{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests.dropOne",
  qemuPackage ? pkgs.qemu-crucible,
  patchStackRepository ?
    import ./_qemu-patch-stack-repository.nix {
      inherit pkgs lib qemuPackage;
    },
  dropOneRepository ?
    import ./_qemu-drop-one-repository.nix {
      inherit pkgs lib qemuPackage patchStackRepository;
    },
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  patchFiles = series.patchFiles;
  patchCount = builtins.length patchFiles;
  patchStackRepositorySource = builtins.readFile ./_qemu-patch-stack-repository.nix;
  dropOneRepositorySource = builtins.readFile ./_qemu-drop-one-repository.nix;
  dropOneBuildSource = builtins.readFile ./_drop-one-build.nix;
  dropOneSource = builtins.readFile ./_drop-one.nix;
  buildEvidenceSource = builtins.readFile ./_drop-one-build-evidence.sh;
  patchRegenerationSource = builtins.readFile ./phase2-qemu-patch-regeneration.nix;
  staticFailures =
    lib.optionals (!(lib.hasInfix "git add -A" patchStackRepositorySource)) [
      "shared patch-stack repository must own the sole full-tree staging pass"
    ]
    ++ lib.optionals (lib.hasInfix "git add -A" dropOneRepositorySource) [
      "drop-one repository must reuse bundle commits without full-tree staging"
    ]
    ++ lib.optionals (lib.hasInfix "git add -A" dropOneBuildSource) [
      "per-patch builds must not reconstruct or stage the patch stack"
    ]
    ++ lib.optionals (lib.hasInfix "tar -xf \${qemuPackage.src}" dropOneBuildSource) [
      "per-patch builds must materialize prepared refs instead of extracting QEMU"
    ]
    ++ lib.optionals (!(lib.hasInfix "source-supplement.tar" dropOneBuildSource)) [
      "per-patch builds must retain QEMU's ignored vendored subprojects"
    ]
    ++ lib.optionals (!(lib.hasInfix "checkout-index" dropOneBuildSource)) [
      "per-patch builds must check out only their prepared shared-repository ref"
    ]
    ++ lib.optionals (!(lib.hasInfix "source_reconstruction_inventory_verified=true" patchStackRepositorySource)) [
      "shared source reconstruction must prove a normalized exact inventory"
    ]
    ++ lib.optionals (!(lib.hasInfix "source_reconstruction_inventory_consumed=true" dropOneBuildSource)) [
      "clean variants must consume the verified source inventory and supplement"
    ]
    ++ lib.optionals (!(lib.hasInfix "diff-files --quiet" dropOneBuildSource)) [
      "clean variants must verify checked-out tracked bytes against the prepared ref"
    ]
    ++ lib.optionals (!(lib.hasInfix "REBASE_HEAD" dropOneRepositorySource)) [
      "drop-one conflicts must identify an exact pinned replay commit"
    ]
    ++ lib.optionals (!(lib.hasInfix "--diff-filter=U" dropOneRepositorySource)) [
      "drop-one conflicts must contain unmerged paths"
    ]
    ++ lib.optionals (!(lib.hasInfix "extract_drop_one_build_evidence" dropOneSource)) [
      "the cheap classifier must parse raw drop-one compiler and linker diagnostics"
    ]
    ++ lib.optionals (!(lib.hasInfix "(fatal )?error:" buildEvidenceSource)) [
      "drop-one symbol evidence must originate from an error or fatal diagnostic"
    ]
    ++ lib.optionals (lib.hasInfix "printf 'path\\t" buildEvidenceSource) [
      "source-path correlation must not classify a drop-one build failure"
    ]
    ++ lib.optionals (lib.hasInfix " -j" dropOneBuildSource) [
      "per-patch builds must not pass an explicit short-form job count"
    ]
    ++ lib.optionals (lib.hasInfix "--jobs" dropOneBuildSource) [
      "per-patch builds must not pass an explicit long-form job count"
    ]
    ++ lib.optionals (lib.hasInfix "NIX_BUILD_CORES" dropOneBuildSource) [
      "per-patch builds must not override Nix-selected build parallelism"
    ]
    ++ lib.optionals (lib.hasInfix "tar -xf \${qemuPackage.src}" patchRegenerationSource) [
      "patch regeneration must reuse the shared verified base repository"
    ];

  # Exported-ABI-symbol discriminators for the patches that expose plugin API
  # symbols (used only if the patch drops clean AND builds -- otherwise the live
  # outcome is source-dependency or build-required). Extracted from each patch's
  # QEMU_PLUGIN_API declarations. Patches with no entry expose no ABI symbol and
  # fall to the semantic discriminator when they drop clean and build.
  symbolDiscriminators = {
    "0006-crucible-clock-deadline.patch" = ["qemu_plugin_clock_deadline_ns"];
    "0009-crucible-net-deterministic.patch" = [
      "qemu_plugin_net_inject"
    ];
    "0010-crucible-plugin-time-advance.patch" = [
      "qemu_plugin_has_time_control"
      "qemu_plugin_register_time_advance_cb"
      "qemu_plugin_advance_time_ns"
    ];
    "0011-crucible-plugin-icount-raw.patch" = ["qemu_plugin_icount_raw"];
    "0012-crucible-plugin-vcpu-exit.patch" = ["qemu_plugin_force_vcpu_exit"];
    "0013-crucible-plugin-wake-fd.patch" = [
      "qemu_plugin_register_wake_fd"
      "qemu_plugin_request_shutdown"
      "qemu_plugin_crucible_single_threaded_rr"
    ];
    "0014-crucible-plugin-tcg-exec-cb.patch" = ["qemu_plugin_register_tcg_exec_cb"];
    "0015-crucible-blk-shmem.patch" = ["qemu_plugin_register_blk_cb"];
    "0018-crucible-dev-cb-api.patch" = ["qemu_plugin_register_9p_cb"];
    "0020-crucible-net-tx-callback.patch" = ["qemu_plugin_register_net_tx_cb"];
    "0025-crucible-sim-idle-callbacks.patch" = ["qemu_plugin_register_vcpu_idle_resume_cb"];
    "0026-crucible-sim-shmem-dispatch.patch" = ["qemu_plugin_register_sim_shmem_dispatch_cb"];
    "0028-crucible-det-ipi.patch" = ["qemu_plugin_crucible_register_ipi_delivery_cb"];
    "0029-crucible-vcpu-introspect.patch" = [
      "qemu_plugin_read_vcpu_regs"
      "qemu_plugin_rr_cursor"
    ];
    "0030-crucible-preemption-inject.patch" = ["qemu_plugin_inject_preemption"];
    "0033-crucible-sim-observer.patch" = ["qemu_plugin_register_sim_shmem_observer_cb"];
    "0035-crucible-process-argv-attestation.patch" = [
      "qemu_plugin_crucible_process_argv_attestation"
    ];
    "0036-crucible-raw-state-export.patch" = [
      "qemu_plugin_crucible_guest_ram_region_copy"
      "qemu_plugin_crucible_guest_ram_regions"
      "qemu_plugin_crucible_request_terminal_pause"
      "qemu_plugin_crucible_vmstate_snapshot_begin"
      "qemu_plugin_crucible_vmstate_snapshot_copy"
      "qemu_plugin_crucible_vmstate_snapshot_free"
      "qemu_plugin_crucible_vmstate_snapshot_size"
    ];
    "0039-crucible-blk-device-completion-advance.patch" = [
      "qemu_plugin_register_blk_wait_cb"
    ];
    "0040-crucible-9p-sync-kick.patch" = [];
    "0041-crucible-whitebox-guest-write.patch" = [
      "qemu_plugin_crucible_write_memory_vaddr"
      "qemu_plugin_crucible_write_memory_vaddr_for_vcpu"
    ];
    "0042-crucible-aarch64-det-ipi-adapter.patch" = [];
    "0043-crucible-time-advance-commit-barrier.patch" = [];
    "0044-crucible-time-advance-enqueue-kick.patch" = [];
    "0045-crucible-time-advance-arm-at-vcpu-boundary.patch" = [];
    "0046-crucible-translation-prefetch-helper.patch" = [];
    "0047-crucible-fault-command-abi.patch" = [
      "qemu_plugin_crucible_fault_capabilities"
      "qemu_plugin_crucible_fault_submit"
      "qemu_plugin_crucible_fault_cancel"
      "qemu_plugin_crucible_fault_peek"
      "qemu_plugin_crucible_fault_poll"
    ];
    "0048-crucible-fault-safe-boundary.patch" = [];
    "0049-crucible-memory-boundary-mutate.patch" = [];
    "0052-crucible-instruction-and-exception-faults.patch" = [
      "qemu_plugin_crucible_fault_instruction_manifest"
    ];
    "0053-crucible-interrupt-faults.patch" = [
      "qemu_plugin_crucible_fault_interrupt_manifest"
    ];
    "0054-crucible-inject-architecture-hardware-errors.patch" = [
      "qemu_plugin_crucible_fault_hardware_error_manifest"
    ];
    "0055-crucible-vcpu-service-control.patch" = [];
    "0060-crucible-block-typed-errors.patch" = [];
    "0061-crucible-block-discard.patch" = [];
    "0062-crucible-block-transport-reset.patch" = ["qemu_plugin_register_blk_event_cb"];
    "0063-crucible-plugin-vmstop.patch" = ["qemu_plugin_request_vmstop"];
    "0070-crucible-fault-vmstate.patch" = [
      "qemu_plugin_crucible_fault_system_manifest"
    ];
  };

  # Some clean 3-way drops expose a later patch's semantic dependency as a
  # fatal reference to a file-local identifier rather than a missing exported
  # ABI symbol. Bind those cases to both the exact compiler identifier and an
  # exact definition present in the full stack but absent from the prepared
  # variant.
  internalBuildFailureDiscriminators = {
    "0092-crucible-canonical-terminal-rr-cursor.patch" = [
      {
        identifier = "terminal_cursor";
        path = "plugins/api.c";
        fullSourceNeedle = "bool terminal_cursor = !exact_boundary && cpu &&";
      }
    ];
    "0136-crucible-seal-hot-fork-plugin-workers.patch" = [
      {
        identifier = "QEMU_PLUGIN_CRUCIBLE_WORKER_ALL";
        path = "include/qemu/qemu-plugin.h";
        fullSourceNeedle = "#define QEMU_PLUGIN_CRUCIBLE_WORKER_ALL ((UINT64_C(1) << 3) - 1)";
      }
      {
        identifier = "QEMU_PLUGIN_CRUCIBLE_WORKER_REQUIRED";
        path = "include/qemu/qemu-plugin.h";
        fullSourceNeedle = "#define QEMU_PLUGIN_CRUCIBLE_WORKER_REQUIRED ((UINT64_C(1) << 2) - 1)";
      }
    ];
  };

  # These patches intentionally change QEMU's executable test corpus rather
  # than the installed emulator. Their full-minus variants must retain a
  # byte-identical shipped binary, while losing the exact fixture material
  # catalogued here. Every other byte-identical clean drop remains a rejected
  # composition gap.
  testFixtureDiscriminators = {
    "0081-crucible-deferred-result-evidence-test.patch" = [
      {
        path = "tests/tcg/plugins/crucible-instruction.c";
        fullSourceNeedle = "test_compose_mode() && result.command_sequence == 4 ?";
      }
    ];
    "0096-crucible-physical-page-table-region-fixture.patch" = [
      {
        path = "tests/tcg/plugins/crucible-memory-access.c";
        fullSourceNeedle = "test_payload_target(address, length, virtual_address);";
      }
    ];
    "0099-crucible-valid-aarch64-abort-fixture.patch" = [
      {
        path = "tests/tcg/plugins/crucible-memory-access.c";
        fullSourceNeedle = "TEST_AARCH64_DATA_ABORT_SAME_EL_SYNDROME";
      }
    ];
  };

  hasSymbolDiscriminator = patch:
    builtins.hasAttr patch symbolDiscriminators
    && symbolDiscriminators.${patch} != [];
  needsSimDiscriminator = patch:
    !hasSymbolDiscriminator patch
    && !builtins.hasAttr patch testFixtureDiscriminators;

  dropOnes =
    lib.imap (i: patch: let
      index = i + 1;
      symbols =
        if builtins.hasAttr patch symbolDiscriminators
        then symbolDiscriminators.${patch}
        else [];
      internalBuildFailures =
        if builtins.hasAttr patch internalBuildFailureDiscriminators
        then internalBuildFailureDiscriminators.${patch}
        else [];
      testFixtureEvidence =
        if builtins.hasAttr patch testFixtureDiscriminators
        then testFixtureDiscriminators.${patch}
        else [];
      # 0007 (block-rtc-read) forces the sim RTC to the virtual clock; it is only
      # observable when the guest reads a host-backed RTC, so its variant probe
      # runs with -rtc clock=host.
      rtcClock =
        if patch == "0007-crucible-block-rtc-read.patch"
        then "host"
        else "vm";
      buildDrv = import ./_drop-one-build.nix {
        inherit pkgs lib qemuPackage index dropOneRepository;
        attrPath = "${attrPath}.p${toString index}.build";
      };
      priorBehavioralIndexes = builtins.filter (
        prior:
          needsSimDiscriminator (builtins.elemAt patchFiles prior)
      ) (lib.genList (prior: prior) i);
      previousBehavioralDependency =
        if priorBehavioralIndexes == []
        then []
        else let
          prior = builtins.elemAt priorBehavioralIndexes (
            builtins.length priorBehavioralIndexes - 1
          );
        in [(builtins.elemAt dropOnes prior).simDiverge];
      simDiverge = import ./_sim-diverge.nix {
        inherit pkgs lib index qemuPackage buildDrv rtcClock;
        attrPath = "${attrPath}.p${toString index}.simDiverge";
        dependencies = previousBehavioralDependency;
      };
    in {
      inherit index patch symbols simDiverge;
      drv = import ./_drop-one.nix {
        inherit pkgs lib qemuPackage index rtcClock dropOneRepository buildDrv simDiverge;
        expectAbsentSymbols = symbols;
        expectInternalBuildFailures = internalBuildFailures;
        expectTestFixtureEvidence = testFixtureEvidence;
        attrPath = "${attrPath}.p${toString index}";
      };
    })
    patchFiles;

  # Passing this dependency-rich inventory as a file keeps the aggregate
  # builder environment comfortably below Linux's argv/environment ceiling.
  perPatchManifest =
    lib.concatMapStringsSep "\n" (
      entry: "${toString entry.index}\t${entry.patch}\t${entry.drv}"
    )
    dropOnes
    + "\n";

  buildFailureEvidencePolicy = pkgs.mkDerivation {
    pname = "crucible-drop-one-build-evidence-policy";
    version = "0";
    src = null;

    buildDeps = [pkgs.coreutils pkgs.grep pkgs.sed];

    phases = [
      {
        name = "check-build-evidence-policy";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"
          . ${./_drop-one-build-evidence.sh}

          printf '%s\n' qemu_plugin_expected > "$TMPDIR/full-exports"
          printf 'path\t%s\n' accel/tcg/tcg-all.c > "$TMPDIR/path-only"
          if validate_drop_one_build_evidence \
            "$TMPDIR/path-only" "$TMPDIR/full-exports" qemu_plugin_expected ""; then
            echo "FAIL: source-path correlation was accepted as causal evidence" >&2
            exit 1
          fi

          cat > "$TMPDIR/warning-plus-unrelated-failure.log" <<'LOG'
          source.c:1:2: warning: implicit declaration of function 'qemu_plugin_expected'
          ninja: build stopped: interrupted by user
          LOG
          extract_drop_one_build_evidence \
            "$TMPDIR/warning-plus-unrelated-failure.log" \
            "$TMPDIR/warning-evidence" "$TMPDIR/warning-diagnostics"
          if validate_drop_one_build_evidence \
            "$TMPDIR/warning-evidence" "$TMPDIR/full-exports" \
            qemu_plugin_expected ""; then
            echo "FAIL: nonfatal exact-symbol warning was accepted as causal evidence" >&2
            exit 1
          fi

          cat > "$TMPDIR/linker-warning-plus-unrelated-failure.log" <<'LOG'
          link-wrapper: warning: undefined reference to `qemu_plugin_expected'
          collect2: error: ld returned 1 exit status
          ninja: build stopped: interrupted by user
          LOG
          extract_drop_one_build_evidence \
            "$TMPDIR/linker-warning-plus-unrelated-failure.log" \
            "$TMPDIR/linker-warning-evidence" \
            "$TMPDIR/linker-warning-diagnostics"
          if validate_drop_one_build_evidence \
            "$TMPDIR/linker-warning-evidence" "$TMPDIR/full-exports" \
            qemu_plugin_expected ""; then
            echo "FAIL: nonfatal linker warning was accepted as causal evidence" >&2
            exit 1
          fi

          cat > "$TMPDIR/embedded-error-warning.log" <<'LOG'
          source.c:1:2: warning: prior error: implicit declaration of function 'qemu_plugin_expected'
          ninja: build stopped: interrupted by user
          LOG
          extract_drop_one_build_evidence \
            "$TMPDIR/embedded-error-warning.log" \
            "$TMPDIR/embedded-error-warning-evidence" \
            "$TMPDIR/embedded-error-warning-diagnostics"
          if validate_drop_one_build_evidence \
            "$TMPDIR/embedded-error-warning-evidence" "$TMPDIR/full-exports" \
            qemu_plugin_expected ""; then
            echo "FAIL: warning with embedded error text was accepted as causal evidence" >&2
            exit 1
          fi

          cat > "$TMPDIR/exact-fatal.log" <<'LOG'
          source.c:1:2: error: implicit declaration of function 'qemu_plugin_expected'
          LOG
          extract_drop_one_build_evidence \
            "$TMPDIR/exact-fatal.log" "$TMPDIR/exact-fatal-evidence" \
            "$TMPDIR/exact-fatal-diagnostics"
          validate_drop_one_build_evidence \
            "$TMPDIR/exact-fatal-evidence" "$TMPDIR/full-exports" \
            qemu_plugin_expected ""

          printf 'symbol\t%s\n' qemu_plugin_unrelated > "$TMPDIR/unrelated-symbol"
          if validate_drop_one_build_evidence \
            "$TMPDIR/unrelated-symbol" "$TMPDIR/full-exports" qemu_plugin_expected ""; then
            echo "FAIL: unrelated compiler symbol was accepted as causal evidence" >&2
            exit 1
          fi

          printf 'symbol\t%s\n' qemu_plugin_expected > "$TMPDIR/exact-symbol"
          validate_drop_one_build_evidence \
            "$TMPDIR/exact-symbol" "$TMPDIR/full-exports" qemu_plugin_expected ""

          cat > "$out/result" <<RESULT
          PASS
          path_only_build_failure_rejected=true
          unrelated_symbol_build_failure_rejected=true
          exact_symbol_warning_plus_unrelated_failure_rejected=true
          linker_warning_plus_unrelated_failure_rejected=true
          embedded_error_warning_plus_unrelated_failure_rejected=true
          exact_manifest_symbol_build_failure_accepted=true
          RESULT
        '';
      }
    ];
  };
in
  if staticFailures != []
  then throw "crucible QEMU drop-one setup regression: ${builtins.concatStringsSep "; " staticFailures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-patch-drop-one";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.gawk pkgs.grep];
      PATCH_COUNT = toString patchCount;
      passAsFile = ["perPatchManifest"];
      inherit perPatchManifest;

      phases = [
        {
          name = "aggregate-drop-one-attribution";
          script = ''
            set -eu
            export LC_ALL=C
            mkdir -p "$out/per-patch"
            : > "$out/methods.tsv"

            grep -q '^PASS$' ${patchStackRepository}/result
            grep -q '^source_extractions=1$' ${patchStackRepository}/result
            grep -q '^full_tree_staging_passes=1$' ${patchStackRepository}/result
            grep -q '^ignored_vendored_subprojects_preserved=true$' \
              ${patchStackRepository}/result
            grep -q '^source_reconstruction_inventory_verified=true$' \
              ${patchStackRepository}/result
            grep -q '^PASS$' ${dropOneRepository}/result
            grep -q '^all_drop_one_branches_computed_in_one_repository=true$' \
              ${dropOneRepository}/result
            grep -q '^conflicts_require_pinned_rebase_head_and_unmerged_paths=true$' \
              ${dropOneRepository}/result
            grep -q '^successful_refs_bind_materialized_source_identity=true$' \
              ${dropOneRepository}/result
            grep -q '^PASS$' ${buildFailureEvidencePolicy}/result
            grep -q '^path_only_build_failure_rejected=true$' \
              ${buildFailureEvidencePolicy}/result
            grep -q '^unrelated_symbol_build_failure_rejected=true$' \
              ${buildFailureEvidencePolicy}/result
            grep -q '^exact_symbol_warning_plus_unrelated_failure_rejected=true$' \
              ${buildFailureEvidencePolicy}/result
            grep -q '^linker_warning_plus_unrelated_failure_rejected=true$' \
              ${buildFailureEvidencePolicy}/result
            grep -q '^embedded_error_warning_plus_unrelated_failure_rejected=true$' \
              ${buildFailureEvidencePolicy}/result
            grep -q '^exact_manifest_symbol_build_failure_accepted=true$' \
              ${buildFailureEvidencePolicy}/result
            cp ${dropOneRepository}/drop-one-manifest.tsv \
              "$out/drop-one-repository-manifest.tsv"

            tab=$(printf '\t')
            while IFS="$tab" read -r index patch drv; do
              test -n "$index"
              test -n "$patch"
              test -n "$drv"
              result="$drv/result"
              grep -q '^PASS$' "$result"
              grep -q "^dropped_patch=$patch$" "$result"
              cp "$result" "$out/per-patch/$patch.result"
              method=$(gawk -F= '/^attribution_method=/ { print $2 }' "$result")
              if [ "$method" != drop-one-source-dependency ]; then
                grep -q '^source_reconstruction_inventory_consumed=true$' "$result"
                grep -q '^materialized_source_identity=[0-9a-f]\{64\}$' "$result"
              fi
              if [ "$method" = drop-one-build-required ]; then
                grep -q '^exact_manifest_build_failure_evidence=true$' "$result"
              fi
              if [ "$method" = drop-one-binary ]; then
                grep -q '^assembly_reference_patch=0081-crucible-deferred-result-evidence-test.patch$' "$result"
                grep -q '^assembly_reference_executable_sha256=[0-9a-f]\{64\}$' "$result"
                grep -q '^variant_executable_sha256=[0-9a-f]\{64\}$' "$result"
                grep -q '^same_builder_executable_changes_without_patch=true$' "$result"
              fi
              if [ "$method" = drop-one-test-fixture ]; then
                grep -q '^assembly_reference_patch=0081-crucible-deferred-result-evidence-test.patch$' "$result"
                grep -q '^same_builder_executable_byte_identical=true$' "$result"
                grep -q '^exact_test_fixture_source_loss_verified=true$' "$result"
                grep -Eq '^test_fixture_evidence_count=[1-9][0-9]*$' "$result"
              fi
              printf '%s\t%s\t%s\n' "$index" "$patch" "$method" \
                >> "$out/methods.tsv"
            done < "$perPatchManifestPath"

            # Every patch resolves to exactly one recognized attribution method.
            bad=$(gawk -F'\t' '
              $3 != "drop-one-source-dependency" &&
              $3 != "drop-one-build-required" &&
              $3 != "drop-one-symbol" &&
              $3 != "drop-one-semantic" &&
              $3 != "drop-one-binary" &&
              $3 != "drop-one-test-fixture" &&
              $3 != "drop-one-composition" &&
              $3 != "structural-fallback" { print }
            ' "$out/methods.tsv")
            if [ -n "$bad" ]; then
              echo "patches without a recognized drop-one method:" >&2
              printf '%s\n' "$bad" >&2
              exit 1
            fi

            rows=$(wc -l < "$out/methods.tsv" | tr -d ' ')
            test "$rows" -eq "$PATCH_COUNT"

            count() { gawk -F'\t' -v m="$1" '$3==m{c++} END{print c+0}' "$out/methods.tsv"; }
            n_srcdep=$(count drop-one-source-dependency)
            n_build=$(count drop-one-build-required)
            n_symbol=$(count drop-one-symbol)
            n_semantic=$(count drop-one-semantic)
            n_binary=$(count drop-one-binary)
            n_test_fixture=$(count drop-one-test-fixture)
            n_composition=$(count drop-one-composition)
            n_fallback=$(count structural-fallback)
            test "$n_composition" -eq 0
            test "$n_fallback" -eq 0

            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            gate=gate:patch-microtests
            patch_count=${toString patchCount}
            every_patch_has_exactly_one_drop_one_method=true
            clean_conflict_split_recomputed_live=true
            shared_patch_stack_source_extractions=1
            shared_patch_stack_full_tree_staging_passes=1
            shared_patch_stack_preserves_ignored_vendored_subprojects=true
            shared_source_reconstruction_inventory_verified=true
            all_drop_one_branches_computed_in_one_repository=true
            conflicts_require_pinned_rebase_head_and_unmerged_paths=true
            build_failures_require_exact_manifest_fatal_diagnostics=true
            internal_build_failures_require_full_minus_variant_source_proof=true
            hostile_unrelated_build_failure_negative_control=true
            successful_variants_verify_tracked_tree_and_source_identity=true
            successful_variants_materialize_prepared_refs=true
            conflict_variants_skip_source_checkout=true
            drop_one_repository_manifest=drop-one-repository-manifest.tsv
            drop_one_source_dependency_count=$n_srcdep
            drop_one_build_required_count=$n_build
            drop_one_symbol_count=$n_symbol
            drop_one_semantic_count=$n_semantic
            drop_one_binary_count=$n_binary
            drop_one_test_fixture_count=$n_test_fixture
            drop_one_composition_count=$n_composition
            structural_fallback_count=$n_fallback
            methods_manifest=methods.tsv
            RESULT
          '';
        }
      ];
    }
