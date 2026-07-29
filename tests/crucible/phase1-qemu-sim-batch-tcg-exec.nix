{
  pkgs,
  lib,
  patchName ? "0027-crucible-sim-batch-tcg-exec.patch",
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-qemu-sim-batch-tcg-exec.c;
  simAccelCheck = import ./phase1-sim-accel.nix {inherit pkgs lib qemuPackage;};
  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));
  qemuPackageResultLines =
    if qemuPackage == null
    then ''
      qemu_package=standalone-fixture
      qemu_package_version=standalone-fixture
    ''
    else ''
      qemu_package=${qemuPackage}
      qemu_package_version=${qemuPackage.version}
    '';

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;


  forbiddenPatchNeedles = [
    "QEMU_CLOCK_REALTIME"
    "g_get_monotonic_time"
    "qemu_clock_get_ns(QEMU_CLOCK_REALTIME)"
  ];

  failures =
    lib.optionals (patchName != "0027-crucible-sim-batch-tcg-exec.patch") [
      "tests/crucible/phase1-qemu-sim-batch-tcg-exec.nix: unknown T-PATCH-17 patch ${patchName}"
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuNix [
      {
        label = "QEMU patch wiring for ${patchName}";
        needle = "patch -p1 < \${./qemu-patches/${patchName}}";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "fixed batch limit";
        needle = "RR_CRUCIBLE_SIM_TCG_BATCH_LIMIT";
      }
      {
        label = "single exec outside sim or multi-vCPU sim";
        needle = "if (!rr_crucible_sim_mode() || rr_cpu_count() > 1)";
      }
      {
        label = "batch runner";
        needle = "rr_crucible_sim_run_tcg_batch";
      }
      {
        label = "batch continuation helper";
        needle = "rr_crucible_sim_tcg_batch_continue";
      }
      {
        label = "halted exit break";
        needle = "EXCP_HALTED";
      }
      {
        label = "debug exit break";
        needle = "EXCP_DEBUG";
      }
      {
        label = "atomic exit break";
        needle = "EXCP_ATOMIC";
      }
      {
        label = "timer refresh between slots";
        needle = "qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)";
      }
      {
        label = "budget refresh between slots";
        needle = "rr_crucible_sim_refresh_batch_budget";
      }
      {
        label = "shmem budget clamp reused";
        needle = "crucible_sim_shmem_clamp_cpu_budget";
      }
      {
        label = "shmem dispatch registration guard";
        needle = "crucible_sim_shmem_dispatch_registered()";
      }
      {
        label = "BQL-releasing vCPU ceiling wait";
        needle = "qemu_cond_wait_bql(first_cpu->halt_cond)";
      }
    ]
    ++ lib.optionals (hasInfix "qemu_plugin_main_loop_wait()" patchSource) [
      "pkgs/emulation/qemu-patches/${patchName}: vCPU ceiling path must not run the QEMU main loop"
    ]
    ++ map (needle: "pkgs/emulation/qemu-patches/${patchName}: pure perf patch must not use wall-clock needle `${needle}`")
    (builtins.filter (needle: hasInfix needle patchSource) forbiddenPatchNeedles)
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "T-PATCH-17 checklist complete";
        needle = "- [x] **T-PATCH-17**";
      }
      {
        label = "PATCH-35 cross reference";
        needle = "PATCH-35";
      }
      {
        label = "batch patch catalog";
        needle = "crucible-sim-batch-tcg-exec";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes QEMU sim batch TCG exec check";
        needle = "qemuSimBatchTcgExec = import ./phase1-qemu-sim-batch-tcg-exec.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU sim batch TCG exec check failed for ${patchName}:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-sim-batch-tcg-exec-${lib.removeSuffix ".patch" patchName}";
      version = "0";
      src = null;

      inherit microtestSource;
      passAsFile = ["microtestSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.grep
        pkgs.patch
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "run-qemu-sim-batch-tcg-exec-microtest";
          script = ''
            set -eu

            mkdir -p "$out"
            apply_dir="$TMPDIR/qemu-sim-batch-tcg-exec-apply"
            mkdir -p "$apply_dir"
            tar -xf ${qemuPackage.src} -C "$apply_dir"
            source_dir="$apply_dir/qemu-${qemuPackage.version}"

            if grep -R -q 'rr_crucible_sim_run_tcg_batch' "$source_dir"/accel "$source_dir"/include "$source_dir"/plugins 2>/dev/null; then
              echo "stock source unexpectedly contains rr_crucible_sim_run_tcg_batch" >&2
              exit 1
            fi

            (
              cd "$source_dir"
              for patch in ${builtins.concatStringsSep " " patchFiles}; do
                patch --batch --fuzz=0 -p1 -i "${patchDir}/$patch"
              done

              grep -F -q 'RR_CRUCIBLE_SIM_TCG_BATCH_LIMIT' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_tcg_batch_limit' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_tcg_batch_continue' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_run_tcg_batch' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'EXCP_HALTED' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'EXCP_DEBUG' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'EXCP_ATOMIC' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'crucible_sim_shmem_clamp_cpu_budget' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'crucible_sim_shmem_dispatch_registered()' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'qemu_cond_wait_bql(first_cpu->halt_cond)' accel/tcg/tcg-accel-ops-rr.c
              ! grep -F -q 'qemu_plugin_main_loop_wait()' accel/tcg/tcg-accel-ops-rr.c
            )

            cp "$microtestSourcePath" phase1-qemu-sim-batch-tcg-exec.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              phase1-qemu-sim-batch-tcg-exec.c \
              -o phase1-qemu-sim-batch-tcg-exec
            ./phase1-qemu-sim-batch-tcg-exec > "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^PASS$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_single_vcpu_fixed_limit=true$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_multivcpu_limit_guard=true$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_on_off_icount_trace_identical=true$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_halted_returns_to_rr_handoff=true$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_breaks_on_debug_atomic=true$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_timer_between_slots=true$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_shmem_ceiling_guard=true$' "$out/qemu-sim-batch-tcg-exec-microtest"
            grep -q '^sim_batch_tcg_exec_ceiling_wait_releases_bql=true$' "$out/qemu-sim-batch-tcg-exec-microtest"

            cp "${simAccelCheck}/result" "$out/sim-accel.result"
            grep -q '^PASS$' "$out/sim-accel.result"
            grep -q '^sim_accel_fixed_icount_tb_trace_identical=true$' "$out/sim-accel.result"

            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.qemuSimBatchTcgExec
            gate=gate:layer0-determinism
            gate=gate:single-vm-fingerprint
            gate=gate:patch-microtests
            tasks=T-PATCH-17
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            sim_batch_tcg_exec_patch_applies=true
            sim_batch_tcg_exec_single_vcpu_fixed_limit=true
            sim_batch_tcg_exec_multivcpu_limit_guard=true
            sim_batch_tcg_exec_on_off_icount_trace_identical=true
            sim_batch_tcg_exec_halted_returns_to_rr_handoff=true
            sim_batch_tcg_exec_breaks_on_debug_atomic=true
            sim_batch_tcg_exec_timer_between_slots=true
            sim_batch_tcg_exec_shmem_ceiling_guard=true
            sim_accel_fixed_icount_tb_trace_identical=true
            RESULT
          '';
        }
      ];
    }
