{
  pkgs,
  lib,
  patchName ? "0021-crucible-sim-loop-fix.patch",
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  microtestSource = builtins.readFile ./phase1-qemu-sim-correctness.c;
  simAccelCheck = import ./phase1-sim-accel.nix {inherit pkgs lib qemuPackage;};
  pluginTimeAdvanceCheck = import ./phase1-plugin-time-advance.nix {inherit pkgs lib qemuPackage;};
  patchFiles =
    builtins.sort builtins.lessThan
    (builtins.filter
      (name: lib.hasSuffix ".patch" name)
      (builtins.attrNames (builtins.readDir patchDir)));
  tPatch16PatchNames = [
    "0021-crucible-sim-loop-fix.patch"
    "0022-crucible-sim-first-exit.patch"
    "0023-crucible-sim-skip-second-events.patch"
    "0024-crucible-sim-poll-immediate.patch"
    "0025-crucible-sim-idle-callbacks.patch"
    "0026-crucible-sim-shmem-dispatch.patch"
  ];
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

  patchRequirements =
    if patchName == "0021-crucible-sim-loop-fix.patch"
    then [
      {
        label = "sim mode guard";
        needle = "rr_crucible_sim_mode";
      }
      {
        label = "single-vCPU direct loop CPU";
        needle = "rr_crucible_sim_loop_cpu";
      }
      {
        label = "deterministic exit-request reset";
        needle = "rr_crucible_sim_reset_exit_request";
      }
      {
        label = "current accelerator guard";
        needle = ''current_accel_name(), "sim"'';
      }
    ]
    else if patchName == "0022-crucible-sim-first-exit.patch"
    then [
      {
        label = "first-exit helper";
        needle = "rr_crucible_sim_normalize_first_exit";
      }
      {
        label = "first-exit ordered write";
        needle = "qatomic_set_mb(&cpu->exit_request, 1)";
      }
    ]
    else if patchName == "0023-crucible-sim-skip-second-events.patch"
    then [
      {
        label = "skip second events helper";
        needle = "rr_crucible_sim_skip_second_events_pass";
      }
      {
        label = "inline timer dispatch rationale";
        needle = "time-control advances already run virtual timers inline";
      }
      {
        label = "second events pass gated";
        needle = "if (!rr_crucible_sim_skip_second_events_pass(cpu))";
      }
      {
        label = "pending CPU work preserved";
        needle = "cpu_work_list_empty(cpu)";
      }
      {
        label = "stop request preserved";
        needle = "!cpu->stop";
      }
      {
        label = "unplug request preserved";
        needle = "!cpu->unplug";
      }
    ]
    else if patchName == "0024-crucible-sim-poll-immediate.patch"
    then [
      {
        label = "event-driven wake callback";
        needle = "crucible_shmem_wake";
      }
      {
        label = "pending request coroutine queue";
        needle = "CoQueue pending_requests";
      }
      {
        label = "pending queue cross-context lock";
        needle = "QemuMutex pending_lock";
      }
      {
        label = "lost-wake generation";
        needle = "uint64_t wake_generation";
      }
      {
        label = "wake-driven coroutine resumption";
        needle = "qemu_co_enter_all(&waiters, NULL)";
      }
      {
        label = "wake snapshot prevents requeue loop";
        needle = "waiters = s->pending_requests";
      }
      {
        label = "coroutine park without spin";
        needle = "qemu_co_queue_wait(&s->pending_requests, &s->pending_lock)";
      }
      {
        label = "wake failure propagation";
        needle = "s->wake_failed = true";
      }
      {
        label = "notifier lifetime cleanup";
        needle = "qemu_plugin_wake_notifier_remove(&s->wake_notifier)";
      }
    ]
    else if patchName == "0025-crucible-sim-idle-callbacks.patch"
    then [
      {
        label = "idle resume callback typedef";
        needle = "qemu_plugin_vcpu_idle_resume_cb_t";
      }
      {
        label = "idle resume registration";
        needle = "qemu_plugin_register_vcpu_idle_resume_cb";
      }
      {
        label = "per-vCPU halt callback synchronization";
        needle = "rr_crucible_sim_sync_vcpu_halt_callbacks";
      }
      {
        label = "per-vCPU resume callback boundary";
        needle = "qemu_plugin_maybe_fire_vcpu_resume_cb(cpu)";
      }
      {
        label = "idle callback storage avoids plugin-core symbol collision";
        needle = "qemu_plugin_vcpu_idle_resume_idle_cb";
      }
      {
        label = "all-vCPU halted guard";
        needle = "rr_crucible_sim_all_vcpus_halted";
      }
      {
        label = "queued idle-advance work handoff";
        needle = "rr_crucible_sim_drain_vcpu_work";
      }
      {
        label = "pending advance suppresses resume";
        needle = "qemu_plugin_time_advance_is_pending()";
      }
      {
        label = "still-idle callback resynchronization";
        needle = "rr_crucible_sim_sync_vcpu_halt_callbacks();";
      }
      {
        # A parked-pending vCPU drains queued run_on_cpu work before re-parking,
        # so a main-thread run_on_cpu (e.g. a machine-reset device callback)
        # cannot deadlock against the main-loop-dispatched advance completion.
        # The behavioral guard is the live idle-jump gate; this pins the drain.
        label = "parked-pending vCPU drains queued work";
        needle = "every vCPU's FIFO work queue";
      }
    ]
    else [
      {
        label = "sim shmem source";
        needle = "tcg-accel-ops-sim-shmem.c";
      }
      {
        label = "sim shmem callback typedef";
        needle = "qemu_plugin_sim_shmem_max_advance_icount_cb_t";
      }
      {
        label = "sim shmem callback registration";
        needle = "qemu_plugin_register_sim_shmem_dispatch_cb";
      }
      {
        label = "current icount publish";
        needle = "crucible_sim_shmem_publish_current_icount";
      }
      {
        label = "max advance ceiling";
        needle = "crucible_sim_shmem_may_advance_to";
      }
      {
        label = "budget clamp helper";
        needle = "crucible_sim_shmem_clamp_cpu_budget";
      }
      {
        label = "dispatch registration guard";
        needle = "crucible_sim_shmem_dispatch_registered";
      }
      {
        label = "RR loop budget clamp";
        needle = "cpu_budget = crucible_sim_shmem_clamp_cpu_budget";
      }
      {
        label = "RR loop ceiling wait";
        needle = "qemu_cond_wait_bql(first_cpu->halt_cond)";
      }
    ];

  primaryNeedle =
    if patchName == "0021-crucible-sim-loop-fix.patch"
    then "rr_crucible_sim_loop_cpu"
    else if patchName == "0022-crucible-sim-first-exit.patch"
    then "rr_crucible_sim_normalize_first_exit"
    else if patchName == "0023-crucible-sim-skip-second-events.patch"
    then "rr_crucible_sim_skip_second_events_pass"
    else if patchName == "0024-crucible-sim-poll-immediate.patch"
    then "crucible_shmem_wake"
    else if patchName == "0025-crucible-sim-idle-callbacks.patch"
    then "qemu_plugin_register_vcpu_idle_resume_cb"
    else "crucible_sim_shmem_publish_current_icount";

  failures =
    lib.optionals (!(builtins.elem patchName tPatch16PatchNames)) [
      "tests/crucible/phase1-qemu-sim-correctness.nix: unknown T-PATCH-16 patch ${patchName}"
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuNix (
      map (name: {
        label = "QEMU patch wiring for ${name}";
        needle = "patch -p1 < \${./qemu-patches/${name}}";
      })
      tPatch16PatchNames
    )
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements
    ++ lib.optionals (
      patchName
      == "0024-crucible-sim-poll-immediate.patch"
      && (hasInfix "main_loop_wait(" patchSource
        || hasInfix "aio_poll(" patchSource
        || hasInfix "aio_bh_poll(" patchSource)
    ) [
      "pkgs/emulation/qemu-patches/${patchName}: wake-driven block completion must not re-enter or poll the main loop"
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "PATCH-34 cross reference";
        needle = "PATCH-34";
      }
      {
        label = "sim loop patch catalog";
        needle = "crucible-sim-loop-fix";
      }
      {
        label = "sim shmem dispatch patch catalog";
        needle = "crucible-sim-shmem-dispatch";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes QEMU sim-correctness check";
        needle = "qemuSimCorrectness = import ./phase1-qemu-sim-correctness.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 QEMU sim-correctness check failed for ${patchName}:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-qemu-sim-correctness-${lib.removeSuffix ".patch" patchName}";
      version = "0";
      src = null;

      inherit microtestSource;
      passAsFile = ["microtestSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.diffutils
        pkgs.gawk
        pkgs.grep
        pkgs.patch
        pkgs.tar
        pkgs.xz
      ];

      phases = [
        {
          name = "run-qemu-sim-correctness-microtest";
          script = ''
            set -eu

            mkdir -p "$out"
            apply_dir="$TMPDIR/qemu-sim-correctness-apply"
            mkdir -p "$apply_dir"
            tar -xf ${qemuPackage.src} -C "$apply_dir"
            source_dir="$apply_dir/qemu-${qemuPackage.version}"

            if grep -R -q '${primaryNeedle}' "$source_dir"/accel "$source_dir"/block "$source_dir"/include "$source_dir"/plugins 2>/dev/null; then
              echo "stock source unexpectedly contains ${primaryNeedle}" >&2
              exit 1
            fi

            (
              cd "$source_dir"
              for patch in ${builtins.concatStringsSep " " patchFiles}; do
                patch --batch --fuzz=0 -p1 -i "${patchDir}/$patch"
              done

              grep -F -q 'rr_crucible_sim_loop_cpu' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_normalize_first_exit' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_skip_second_events_pass' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'cpu_work_list_empty(cpu)' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'crucible_shmem_wake' block/crucible-shmem.c
              grep -F -q 'qemu_co_queue_wait(&s->pending_requests, &s->pending_lock)' block/crucible-shmem.c
              grep -F -q 's->wake_generation != observed_generation' block/crucible-shmem.c
              grep -F -q 'qemu_plugin_register_vcpu_idle_resume_cb' include/qemu/qemu-plugin.h
              grep -F -q 'qemu_plugin_maybe_fire_vcpu_idle_cb' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_all_vcpus_halted' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_drain_vcpu_work' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'qemu_plugin_time_advance_is_pending()' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'rr_crucible_sim_sync_vcpu_halt_callbacks' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'tcg-accel-ops-sim-shmem.c' accel/tcg/meson.build
              grep -F -q 'qemu_plugin_register_sim_shmem_dispatch_cb' include/qemu/qemu-plugin.h
              grep -F -q 'crucible_sim_shmem_publish_current_icount' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'crucible_sim_shmem_dispatch_registered()' accel/tcg/tcg-accel-ops-rr.c
              grep -F -q 'crucible_sim_shmem_clamp_cpu_budget' accel/tcg/tcg-accel-ops-sim-shmem.c
              grep -F -q 'qemu_cond_wait_bql(first_cpu->halt_cond)' accel/tcg/tcg-accel-ops-rr.c
              ! grep -F -q 'qemu_plugin_main_loop_wait()' accel/tcg/tcg-accel-ops-rr.c
            )

            cp "$microtestSourcePath" phase1-qemu-sim-correctness.c
            cc -std=c11 -O2 -Wall -Wextra -Werror \
              phase1-qemu-sim-correctness.c \
              -o phase1-qemu-sim-correctness
            ./phase1-qemu-sim-correctness > "$out/qemu-sim-correctness-microtest"
            grep -q '^PASS$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_loop_bookkeeping_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_first_exit_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_skip_second_events_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_second_events_lifecycle_work_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_block_wake_coqueue_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_block_prepark_wake_not_lost=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_block_wake_failure_fails_waiter=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_idle_callbacks_missed_wake_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_idle_advance_completion_barrier_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_idle_advance_rearms_while_halted=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_shmem_dispatch_inert_without_callbacks=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_shmem_dispatch_ceiling_microtest=true$' "$out/qemu-sim-correctness-microtest"
            grep -q '^sim_shmem_budget_clamp_microtest=true$' "$out/qemu-sim-correctness-microtest"

            cp "${simAccelCheck}/result" "$out/sim-accel.result"
            grep -q '^PASS$' "$out/sim-accel.result"
            grep -q '^sim_accel_fixed_icount_tb_trace_identical=true$' "$out/sim-accel.result"
            cp "${pluginTimeAdvanceCheck}/result" "$out/plugin-time-advance.result"
            grep -q '^PASS$' "$out/plugin-time-advance.result"
            grep -q '^callback_entry_is_enqueue_only=true$' "$out/plugin-time-advance.result"
            grep -q '^queued_main_loop_worker_runs_virtual_timers=true$' "$out/plugin-time-advance.result"
            grep -q '^completion_uses_normal_main_loop_bh=true$' "$out/plugin-time-advance.result"
            grep -q '^callback_path_main_loop_reentry_absent=true$' "$out/plugin-time-advance.result"

            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.qemuSimCorrectness
            gate=gate:layer0-determinism
            gate=gate:layer1-injection
            gate=gate:qemu-inert
            gate=gate:patch-microtests
            tasks=T-PATCH-16
            patch=${patchName}
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            sim_correctness_patch_stack_applies=true
            sim_loop_fix_present=true
            sim_first_exit_present=true
            sim_skip_second_events_present=true
            sim_block_wake_coqueue_present=true
            sim_idle_callbacks_present=true
            sim_shmem_dispatch_present=true
            sim_correctness_fixture_exercised=true
            sim_loop_bookkeeping_microtest=true
            sim_first_exit_microtest=true
            sim_skip_second_events_microtest=true
            sim_second_events_lifecycle_work_microtest=true
            sim_block_wake_coqueue_microtest=true
            sim_block_prepark_wake_not_lost=true
            sim_block_wake_failure_fails_waiter=true
            sim_block_main_loop_reentry_absent=true
            sim_idle_callbacks_missed_wake_microtest=true
            sim_idle_advance_completion_barrier_microtest=true
            sim_idle_advance_rearms_while_halted=true
            sim_shmem_dispatch_inert_without_callbacks=true
            sim_shmem_dispatch_ceiling_microtest=true
            sim_shmem_budget_clamp_microtest=true
            bit_exact_cross_run_icount_trace=true
            RESULT
          '';
        }
      ];
    }
