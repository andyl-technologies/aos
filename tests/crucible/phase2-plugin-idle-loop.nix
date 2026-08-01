{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginIdleLoop",
  taskIds ? ["T-PLUG-5"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginIdleLoopTests = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop/tests/inbound_cases.rs)
    (builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop/tests/wake_cases.rs)
  ];
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  pluginDeadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  shmemFrameNode =
    builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/futex.rs;
  shmemRegion = builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenIdlePathApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time"
    "thread::sleep"
    "park_timeout"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
  ];

  idlePathForbiddenFailures =
    lib.concatMap (
      api:
        lib.optionals (hasInfix api pluginIdleLoop) [
          "crates/crucible-qemu-plugin/src/idle_loop.rs: forbidden wall-clock, timeout, or entropy API in idle path: `${api}`"
        ]
    )
    forbiddenIdlePathApis;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-5 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginQuantum`";
      }
      {
        label = "idle callback hot loop text";
        needle = "idle (HLT/WFI) callback hot loop";
      }
      {
        label = "no busy spin text";
        needle = "no busy spin";
      }
      {
        label = "no wall-clock timeout text";
        needle = "no wall-clock timeout";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "idle_loop module exported";
        needle = "pub mod idle_loop;";
      }
      {
        label = "idle loop type exported";
        needle = "PluginIdleHotLoop";
      }
      {
        label = "idle loop error exported";
        needle = "IdleHotLoopError";
      }
      {
        label = "idle wait outcome exported";
        needle = "IdleWaitOutcome";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "idle loop type";
        needle = "pub struct PluginIdleHotLoop";
      }
      {
        label = "begin idle publisher";
        needle = "pub fn begin_idle";
      }
      {
        label = "wake plan computation";
        needle = "pub fn compute_idle_wake_plan";
      }
      {
        label = "timer deadline conversion";
        needle = "pub fn timer_deadline_icount";
      }
      {
        label = "futex release wait";
        needle = "pub fn wait_for_scheduler_release";
      }
      {
        label = "shared region control input";
        needle = "header: &RegionHeader";
      }
      {
        label = "global control action observation";
        needle = "PluginShmemOrdering::observe_control_action";
      }
      {
        label = "shutdown control branch";
        needle = "RegionControlAction::Shutdown";
      }
      {
        label = "shutdown wait outcome";
        needle = "IdleWaitOutcome::ShutdownRequested";
      }
      {
        label = "shutdown marks node done";
        needle = "PluginShmemOrdering::mark_done_after_shutdown";
      }
      {
        label = "scheduler release completion";
        needle = "pub fn complete_after_scheduler_wake";
      }
      {
        label = "resume boundary publisher";
        needle = "pub fn publish_resume_boundary";
      }
      {
        label = "shared-memory idle publish";
        needle = "PluginShmemOrdering::publish_idle_wait";
      }
      {
        label = "shared-memory reached publish";
        needle = "PluginShmemOrdering::publish_reached_icount";
      }
      {
        label = "non-private futex wait";
        needle = "PluginShmemOrdering::wait_on_wake_signal";
      }
      {
        label = "scheduler-authorized idle jump";
        needle = "authorize_idle_jump";
      }
      {
        label = "idle jump advance";
        needle = "advance_authorized_idle_jump";
      }
      {
        label = "deterministic frame injection ordering";
        needle = "PluginInboundFrames::select_deliverable_frames";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop/tests" pluginIdleLoopTests [
      {
        label = "timer/inbound/ceiling wake test";
        needle = "idle_loop_computes_wake_from_timer_inbound_and_ceiling";
      }
      {
        label = "futex wait publish test";
        needle = "idle_loop_publishes_current_then_idle_and_prepares_futex_wait";
      }
      {
        label = "no wall-clock wait test";
        needle = "idle_loop_wait_uses_futex_release_without_wall_clock_timeout";
      }
      {
        label = "authorized release waits for queued-advance completion test";
        needle = "idle_loop_release_waits_for_qemu_completion_before_mutating_state";
      }
      {
        label = "shutdown wake test";
        needle = "idle_loop_shutdown_wake_marks_done_and_returns_teardown_outcome";
      }
      {
        label = "resume boundary test";
        needle = "idle_resume_boundary_republishes_running_without_advancing_time";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "authorized idle jump primitive";
        needle = "pub fn authorize_idle_jump";
      }
      {
        label = "authorized idle jump advance primitive";
        needle = "pub fn advance_authorized_idle_jump";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/deadline.rs" pluginDeadline [
      {
        label = "exact deadline report";
        needle = "pub enum ExactDeadlineReport";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/frame_node.rs" shmemFrameNode [
      {
        label = "idle publish returns futex wait";
        needle = "pub fn publish_idle";
      }
      {
        label = "race-free futex wait decision";
        needle = "pub fn prepare_futex_wait";
      }
      {
        label = "non-private futex wait";
        needle = "pub fn futex_wait_nonprivate";
      }
      {
        label = "node done status publisher";
        needle = "pub fn mark_done";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/shmem/region.rs" shmemRegion [
      {
        label = "region control action";
        needle = "pub fn control_action";
      }
      {
        label = "shutdown request wake-all";
        needle = "pub fn request_shutdown";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin idle loop check";
        needle = "qemuPluginIdleLoop = import ./phase2-plugin-idle-loop.nix";
      }
    ]
    ++ idlePathForbiddenFailures;
in
  if failures != []
  then throw "crucible phase2 plugin idle-loop check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-idle-loop";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            export CARGO_HOME="$TMPDIR/cargo"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-plugin-idle-loop";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-idle-loop-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=partial
            idle_loop=publish-park-authorized-jump-inject-republish
            wake_sources=exact-timer,inbound-delivery,scheduler-ceiling
            wait_primitive=non-private-futex-wake-signal
            no_busy_spin=true
            no_wall_clock_timeout=true
            shutdown_wake=global-control-mark-done
            frame_injection_order=delivery_icount,src_node,seq
            resume_boundary=republish-running-no-advance
            RESULT
          '';
        }
      ];
    }
