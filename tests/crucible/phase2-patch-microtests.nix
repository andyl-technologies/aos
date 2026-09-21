{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.gates.patchMicrotests",
  taskIds ? ["T-PKG-4" "T-HARN-20" "T-PATCH-2" "T-PATCH-20" "T-PATCH-21" "T-PATCH-22" "T-PATCH-23" "T-PATCH-24"],
  openTaskIds ? [],
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchPath = ../../pkgs/emulation/qemu-patches + "/${atomicPatch.file}";
  patchSource = builtins.path {
    path = patchPath;
    name = atomicPatch.file;
  };
  qemu = qemuPackage.passthru or qemuPackage;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  defaultNix = builtins.readFile ./default.nix;
  atomicPatchRepository = import ./_qemu-atomic-patch-repository.nix {
    inherit pkgs qemuPackage;
  };
  qemuPatchRegeneration = import ./phase2-qemu-patch-regeneration.nix {
    inherit pkgs lib qemuPackage atomicPatchRepository;
  };
  checkpointSource = import ./phase2-qemu-checkpoint-delta-source.nix {
    inherit pkgs qemuPackage;
  };
  checkpointFlight = import ./phase2-qemu-checkpoint-delta-flight.nix {
    inherit pkgs lib qemuPackage;
    sourceCheck = checkpointSource;
  };
  diagnosticPolicy = import ./phase1-qemu-diagnostic-patches-dev-only.nix {
    inherit pkgs lib qemuPackage;
  };
  inherit (import ./_lib.nix {inherit lib;}) hasInfix;
  staticFailures =
    lib.optionals (!(hasInfix "atomicPatch ? import ./qemu-patches/_atomic-patch.nix" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU must consume the atomic patch descriptor"
    ]
    ++ lib.optionals (!(hasInfix "< \${atomicPatchPath}" qemuNix)) [
      "pkgs/emulation/qemu.nix: QEMU must apply the atomic patch directly"
    ]
    ++ lib.optionals (!(hasInfix "dependencies = [patchMicrotests.rawGate];" defaultNix)) [
      "tests/crucible/default.nix: gate:qemu-inert must depend on gate:patch-microtests"
    ];
  runtimeInputs =
    [
      pkgs.binutils
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.patch
      pkgs.tar
      pkgs.xz
      qemuPackage
      referenceQemu
    ]
    ++ dependencies;
  runtimeScript = ''
    set -eu
    mkdir -p "$out"

    apply_dir="$TMPDIR/qemu-atomic-patch-apply"
    mkdir -p "$apply_dir"
    tar -xf ${qemuPackage.src} -C "$apply_dir"
    cd "$apply_dir/qemu-${atomicPatch.qemuVersion}"
    patch --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 < ${patchSource}

    grep -Fxq PASS "${atomicPatchRepository}/result"
    grep -Fxq 'apply_commit_tree_verified=true' "${atomicPatchRepository}/result"
    grep -Fxq 'bundle_matches_patch_commit=true' "${atomicPatchRepository}/result"
    grep -Fxq 'source_reconstruction_inventory_verified=true' "${atomicPatchRepository}/result"

    grep -Fxq PASS "${qemuPatchRegeneration}/result"
    grep -Fxq 'atomic_patch_regenerated_exactly=true' "${qemuPatchRegeneration}/result"
    grep -Fxq 'qemu_package_identity_verified=true' "${qemuPatchRegeneration}/result"

    live_result="${checkpointFlight}/result"
    grep -Fxq PASS "$live_result"
    grep -Fxq 'checkpoint_delta_source_prerequisite_passed=true' "$live_result"
    grep -Fxq 'checkpoint_delta_exact_test_passed=1' "$live_result"
    grep -Fxq 'ordinary_mode_checkpoint_test_passed=1' "$live_result"
    grep -Fxq 'ordinary_mode_checkpoint_rejected=true' "$live_result"
    grep -Fxq 'ordinary_mode_inert=true' "$live_result"
    grep -Fxq 'direct_delta_reconstruction_equal=true' "$live_result"
    grep -Fxq 'checkpoint_restore_equal=true' "$live_result"

    grep -Fxq PASS "${diagnosticPolicy}/result"
    grep -Fxq 'qemu_diagnostic_patches_shipped=false' "${diagnosticPolicy}/result"
    grep -Fxq 'dev_only_diagnostic_patches_inert_by_default=true' "${diagnosticPolicy}/result"

    nm -D --defined-only ${qemuPackage}/bin/qemu-system-x86_64 > "$out/patched.symbols"
    nm -D --defined-only ${referenceQemu}/bin/qemu-system-x86_64 > "$out/reference.symbols"
    for symbol in \
      qemu_plugin_clock_deadline_ns \
      qemu_plugin_net_inject \
      qemu_plugin_register_net_tx_cb \
      qemu_plugin_has_time_control \
      qemu_plugin_register_time_advance_cb \
      qemu_plugin_advance_time_ns \
      qemu_plugin_icount_raw \
      qemu_plugin_icount_at_tb_entry \
      qemu_plugin_force_vcpu_exit \
      qemu_plugin_crucible_single_threaded_rr \
      qemu_plugin_register_wake_fd \
      qemu_plugin_request_shutdown \
      qemu_plugin_register_vcpu_idle_resume_cb \
      qemu_plugin_register_sim_shmem_dispatch_cb \
      qemu_plugin_register_sim_shmem_observer_cb \
      qemu_plugin_crucible_fault_dispatch_node_boundary \
      qemu_plugin_crucible_write_memory_vaddr_for_vcpu \
      qemu_plugin_read_vcpu_regs \
      qemu_plugin_register_blk_cb \
      qemu_plugin_register_blk_wait_cb \
      qemu_plugin_register_9p_cb \
      qemu_plugin_inject_preemption \
      qemu_plugin_rr_cursor
    do
      grep -E "[[:space:]]$symbol$" "$out/patched.symbols"
      if grep -E "[[:space:]]$symbol$" "$out/reference.symbols"; then
        echo "reference QEMU unexpectedly exports $symbol" >&2
        exit 1
      fi
    done

    identity_file="${qemuPackage}/share/aos/crucible/qemu-build-identity.env"
    grep -Fxq "qemu_atomic_patch_hash=${atomicPatch.sha256}" "$identity_file"
    grep -Fxq "qemu_patch_branch_head_commit=${atomicPatch.commit}" "$identity_file"
    grep -Fxq "qemu_shmem_abi=${qemu.shmemAbi}" "$identity_file"
    grep -Fxq "qemu_shmem_header_hash=${qemu.shmemHeaderHash}" "$identity_file"
    grep -Fxq 'PASS trap_icount=3 boundary_icount=4' \
      "${qemuPackage}/share/aos/crucible/exact-tb-exit.txt"

    timer_witness_file="${qemuPackage}/share/aos/crucible/virtual-timer-witness.txt"
    timer_witness_result='# timer_witness generation=1 deadline_ns=500 deadline_icount=900 armed_raw_icount=100 fired_expire_ns=500 fired_virtual_ns=504 fired_raw_icount=100 completed=1 reserved=0'
    grep -Fxq "$timer_witness_result" "$timer_witness_file"
    grep -Fxq "qemu_atomic_patch_hash=${atomicPatch.sha256}" "$timer_witness_file"
    grep -Fxq "qemu_shmem_header_hash=${qemu.shmemHeaderHash}" "$timer_witness_file"
    qemu_build_id_line="$(grep '^qemu_build_id=' "$identity_file")"
    test -n "$qemu_build_id_line"
    grep -Fxq "$qemu_build_id_line" "$timer_witness_file"

    cp "${atomicPatchRepository}/result" "$out/repository.result"
    cp "${qemuPatchRegeneration}/result" "$out/regeneration.result"
    cp "$live_result" "$out/behavior.result"
    cp "${diagnosticPolicy}/result" "$out/diagnostic-policy.result"

    cat > "$out/result" <<RESULT
    PASS
    check=${attrPath}
    tasks=${builtins.concatStringsSep "," taskIds}
    open_tasks=${builtins.concatStringsSep "," openTaskIds}
    status=complete
    gate=gate:patch-microtests
    evidence_scope=atomic-apply-commit-tree-build-behavior
    atomic_patch=${atomicPatch.file}
    atomic_patch_hash=${atomicPatch.sha256}
    atomic_patch_commit=${atomicPatch.commit}
    atomic_patch_tree=${atomicPatch.tree}
    apply_clean_pinned_qemu=true
    apply_clean_patch_fuzz=0
    apply_commit_tree_verified=true
    bundle_matches_patch_commit=true
    atomic_patch_regenerated_exactly=true
    patched_qemu_package_build_passed=true
    patched_qemu_package=${qemuPackage}
    patched_qemu_package_version=${qemuPackage.version}
    atomic_patch_runtime_is_shipped_qemu=true
    atomic_patch_live_checkpoint_delta_gate_passed=true
    atomic_patch_live_checkpoint_delta_negative_control=true
    stock_qemu_lacks_atomic_exports=true
    qemu_plugin_clock_deadline_export_present=true
    qemu_plugin_net_exports_present=true
    qemu_plugin_time_drain_exports_present=true
    qemu_plugin_sim_correctness_exports_present=true
    qemu_build_identity_artifact_checked=true
    qemu_build_id_material_includes=qemu_version,qemu_source_hash,qemu_nix_hash,qemu_configure_flags_hash,atomic_patch_hash,patch_branch_bundle_hash,patch_branch_material_hash,qemu_shmem_abi_version,qemu_shmem_header_hash
    exact_tb_exit_test_passed=true
    exact_tb_exit_trap_icount=3
    exact_tb_exit_boundary_icount=4
    timer_witness_identity_bound=true
    timer_witness_deadline_ns=500
    timer_witness_fired_expire_ns=500
    timer_witness_fired_virtual_ns=504
    timer_witness_armed_raw_icount=100
    timer_witness_fired_raw_icount=100
    timer_witness_atomic_patch_hash=${atomicPatch.sha256}
    timer_witness_shmem_header_hash=${qemu.shmemHeaderHash}
    qemu_diagnostic_patches_dev_only_gate_passed=true
    qemu_inert_gate_wired=true
    qemu_inert_depends_on_patch_microtests=true
    qemu_inert_gate_dependency=gate:qemu-inert->gate:patch-microtests
    RESULT
  '';
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase2-atomic-patch-microtests";
    version = "0";
    src = null;
    buildDeps = runtimeInputs;
    phases = [
      {
        name = "verify-atomic-patch";
        script = runtimeScript;
      }
    ];
    passthru = {
      inherit attrPath taskIds openTaskIds dependencies atomicPatchRepository;
      gateName = "gate:patch-microtests";
    };
  };
in
  if staticFailures != []
  then throw "crucible phase2 patch-microtests gate failed:\n${builtins.concatStringsSep "\n" staticFailures}"
  else if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing runtimeInputs runtimeScript;
      inherit (campaignComposition) mode system;
      gateName = "gate:patch-microtests";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "patch-microtests";
      runtimeClosures = [
        qemuPackage.src
        patchSource
        atomicPatchRepository
        qemuPatchRegeneration
        checkpointFlight
        diagnosticPolicy
      ];
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
