{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginSynchronousIdleAdvance",
  taskIds ? ["T-PLUG-7"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  pluginAbiTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests.rs;
  pluginRegistration = import ./_qemu-plugin-registration-source.nix {inherit lib;};
  pluginRuntime = import ./_qemu-plugin-runtime-source.nix {inherit lib;};
  pluginLiveCallbacks = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs;
  pluginLiveCallbacksTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/live_callbacks/tests.rs;
  pluginIdleLoop = builtins.readFile ../../crates/crucible-qemu-plugin/src/idle_loop.rs;
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  qemuPatchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  qemuTimeAdvancePatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0010-crucible-plugin-time-advance.patch;
  qemuIdleCallbacksPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0025-crucible-sim-idle-callbacks.patch;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenTimePathApis = [
    "Instant::now"
    "SystemTime::now"
    "std::time::Instant"
    "std::time::SystemTime"
    "thread::sleep"
    "park_timeout"
    "clock_gettime"
    "gettimeofday"
    "CLOCK_REALTIME"
    "CLOCK_MONOTONIC"
    "thread_rng"
    "rand::random"
  ];

  timePathSources = [
    {
      label = "crates/crucible-qemu-plugin/src/idle_loop.rs";
      content = pluginIdleLoop;
    }
    {
      label = "crates/crucible-qemu-plugin/src/time_control.rs";
      content = pluginTimeControl;
    }
    {
      label = "crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs";
      content = pluginLiveCallbacks;
    }
  ];

  forbiddenTimePathFailures =
    lib.concatMap (
      source:
        lib.concatMap (
          api:
            lib.optionals (hasInfix api source.content) [
              "${source.label}: forbidden host-time, timeout, or entropy API in queued idle path: `${api}`"
            ]
        )
        forbiddenTimePathApis
    )
    timePathSources;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-7 completed by the live plugin quantum gate";
        needle = "- [x] **T-PLUG-7**";
      }
      {
        label = "T-PLUG-7 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginQuantum`";
      }
      {
        label = "queued advance wording";
        needle = "queued-advance (`qemu_plugin_advance_time_ns`) and normal-main-loop completion";
      }
      {
        label = "completion barrier wording";
        needle = "order timer bottom halves before completion";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" qemuPatchSpec [
      {
        label = "queued advance export spec";
        needle = "qemu_plugin_advance_time_ns(ns)";
      }
      {
        label = "queued virtual timer run spec";
        needle = "qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL)";
      }
      {
        label = "bottom-half completion spec";
        needle = "timer-produced main-loop";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0010-crucible-plugin-time-advance.patch" qemuTimeAdvancePatch [
      {
        label = "pending advance predicate";
        needle = "qemu_plugin_time_advance_is_pending";
      }
      {
        label = "pending clears only at normal-loop completion";
        needle = "qatomic_store_release(&qemu_plugin_time_advance_pending, 0)";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0025-crucible-sim-idle-callbacks.patch" qemuIdleCallbacksPatch [
      {
        label = "queued idle-advance handoff";
        needle = "rr_crucible_sim_process_queued_idle_advance";
      }
      {
        label = "pending advance suppresses premature resume";
        needle = "qemu_plugin_time_advance_is_pending()";
      }
      {
        label = "still-idle completion rearm";
        needle = "rr_crucible_sim_maybe_rearm_idle_callback";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "queued advance function pointer exported";
        needle = "QemuAdvanceTimeNsFn";
      }
      {
        label = "queued idle advance exported";
        needle = "QueuedIdleAdvance";
      }
      {
        label = "pending idle advance exported";
        needle = "PendingIdleAdvance";
      }
      {
        label = "time-advance completion exported";
        needle = "TimeAdvanceCompletion";
      }
      {
        label = "time-advance completion callback registration exported";
        needle = "QemuRegisterTimeAdvanceCbFn";
      }
      {
        label = "queued advance resolver exported";
        needle = "resolve_qemu_advance_time_ns_symbol";
      }
      {
        label = "time-capability install helper exported";
        needle = "install_required_time_capability_scaffold_from_qemu_info";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/time_control.rs" pluginTimeControl [
      {
        label = "queued advance symbol constant";
        needle = "QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL";
      }
      {
        label = "queued advance function pointer";
        needle = "pub type QemuAdvanceTimeNsFn = extern \"C\" fn(i64) -> c_int;";
      }
      {
        label = "completion registration symbol constant";
        needle = "QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL";
      }
      {
        label = "completion callback function pointer";
        needle = "pub type QemuTimeAdvanceCompletionCbFn";
      }
      {
        label = "completion registration function pointer";
        needle = "pub type QemuRegisterTimeAdvanceCbFn";
      }
      {
        label = "required queued advance handle";
        needle = "pub struct QueuedIdleAdvance";
      }
      {
        label = "queued advance require constructor";
        needle = "pub fn require";
      }
      {
        label = "optional queued advance rejected";
        needle = "Option<QemuAdvanceTimeNsFn>";
      }
      {
        label = "enqueue method";
        needle = "pub fn enqueue(";
      }
      {
        label = "QEMU queued advance call";
        needle = "(self.advance_time_ns)(qemu_target_ns)";
      }
      {
        label = "pending completion evidence";
        needle = "completion_pending: true";
      }
      {
        label = "completion validation";
        needle = "validate_completion";
      }
      {
        label = "signed QEMU range guard";
        needle = "VirtualTimeOutOfRange";
      }
      {
        label = "authorized target projection";
        needle = "pub fn target_virtual_ns";
      }
      {
        label = "queued advance missing-symbol test";
        needle = "queued_idle_advance_requires_qemu_enqueue_symbol";
      }
      {
        label = "queued advance call test";
        needle = "queued_idle_advance_reports_pending_completion";
      }
      {
        label = "queued advance range test";
        needle = "queued_idle_advance_rejects_targets_outside_qemu_signed_range";
      }
      {
        label = "queued advance completion rejection test";
        needle = "queued_idle_advance_rejects_failed_or_mismatched_completion";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "callback capabilities type";
        needle = "pub struct PluginCallbackCapabilities";
      }
      {
        label = "registration requires queued advance function";
        needle = "QemuAdvanceTimeNsFn";
      }
      {
        label = "registration invokes queued advance require";
        needle = "QueuedIdleAdvance::require";
      }
      {
        label = "queued callback bypass diagnostic";
        needle = "exact deadline and queued idle-advance capabilities";
      }
      {
        label = "missing queued advance registration test";
        needle = "registration_order_fails_loud_when_queued_idle_advance_missing";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/idle_loop.rs" pluginIdleLoop [
      {
        label = "completion takes queued advance capability";
        needle = "queued_idle_advance: &QueuedIdleAdvance";
      }
      {
        label = "idle completion projects authorized target";
        needle = ".target_virtual_ns(clock.icount_shift())";
      }
      {
        label = "idle callback queues the advance";
        needle = ".enqueue(target_virtual_ns)";
      }
      {
        label = "idle result carries completion evidence";
        needle = "pub const fn pending_advance";
      }
      {
        label = "idle completion maps queued advance errors";
        needle = "IdleHotLoopError::QueuedIdleAdvance";
      }
      {
        label = "idle completion entry point";
        needle = "complete_after_time_advance";
      }
      {
        label = "idle pending-completion signal";
        needle = "TimeAdvanceCompletionPending";
      }
      {
        label = "idle range failure test";
        needle = "idle_loop_direct_advance_range_failure_leaves_clock_and_slot_unchanged";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "queued advance dlsym bytes";
        needle = "QEMU_PLUGIN_ADVANCE_TIME_NS_SYMBOL_C";
      }
      {
        label = "queued advance resolver";
        needle = "pub fn resolve_qemu_advance_time_ns_symbol";
      }
      {
        label = "completion registration dlsym bytes";
        needle = "QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL_C";
      }
      {
        label = "completion registration resolver";
        needle = "pub fn resolve_qemu_register_time_advance_cb_symbol";
      }
      {
        label = "queued advance process lookup";
        needle = "libc::dlsym";
      }
      {
        label = "time capability install helper";
        needle = "pub fn install_required_time_capability_scaffold";
      }
      {
        label = "time capability QEMU-info install helper";
        needle = "pub fn install_required_time_capability_scaffold_from_qemu_info";
      }
      {
        label = "install boundary resolves queued advance";
        needle = "resolve_qemu_advance_time_ns_symbol()";
      }
      {
        label = "install boundary resolves completion registration";
        needle = "resolve_qemu_register_time_advance_cb_symbol()";
      }
      {
        label = "ABI error carries queued advance failure";
        needle = "QueuedIdleAdvanceCapability";
      }
      {
        label = "state stores queued advance handle";
        needle = "queued_idle_advance: Some(queued_idle_advance)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi/tests.rs" pluginAbiTests [
      {
        label = "install missing queued advance test";
        needle = "abi_install_requires_queued_idle_advance_symbol";
      }
      {
        label = "entrypoint missing queued advance test";
        needle = "abi_install_entrypoint_requires_queued_advance_after_deadline_resolution";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime.rs" pluginRuntime [
      {
        label = "live install carries completion registration capability";
        needle = "register_time_advance_cb: Option<crate::QemuRegisterTimeAdvanceCbFn>";
      }
      {
        label = "production registrar forwards completion registration";
        needle = "register_time_advance_cb: capabilities.register_time_advance_cb";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/live_callbacks.rs" pluginLiveCallbacks [
      {
        label = "live preflight requires completion registration";
        needle = "QEMU_PLUGIN_REGISTER_TIME_ADVANCE_CB_SYMBOL";
      }
      {
        label = "live registrar installs completion callback";
        needle = "Some(crucible_qemu_plugin_live_time_advance_completion_cb)";
      }
      {
        label = "live idle callback queues QEMU advance";
        needle = ".queued_idle_advance";
      }
      {
        label = "live idle callback arms the exact pending target";
        needle = "self.arm_idle_advance(raw_icount, target_icount, pending)";
      }
      {
        label = "live completion validates and commits pending state";
        needle = "state.complete_idle_advance(TimeAdvanceCompletion::from_qemu";
      }
      {
        label = "live callback registers all-idle and resume boundaries";
        needle = "Some(crucible_qemu_plugin_live_vcpu_idle_cb)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/live_callbacks/tests.rs" pluginLiveCallbacksTests [
      {
        label = "missing completion registration test";
        needle = "missing_time_advance_completion";
      }
      {
        label = "pending state remains unchanged until completion test";
        needle = "live_idle_callback_queues_then_commits_only_from_normal_loop_completion";
      }
      {
        label = "pending idle/resume/reentrancy rejection test";
        needle = "live_pending_advance_rejects_idle_resume_and_reentrant_publication";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin synchronous idle advance check";
        needle = "qemuPluginSynchronousIdleAdvance = import ./phase2-plugin-synchronous-idle-advance.nix";
      }
    ]
    ++ forbiddenTimePathFailures;
in
  if failures != []
  then throw "crucible phase2 plugin synchronous-idle-advance check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-synchronous-idle-advance";
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
          name = "run-plugin-synchronous-idle-advance";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              queued_idle_advance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              abi_install_entrypoint_requires_queued_advance_after_deadline_resolution \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_release_waits_for_qemu_completion_before_mutating_state \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              idle_loop_direct_advance_range_failure_leaves_clock_and_slot_unchanged \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              live_idle_callback_queues_then_commits_only_from_normal_loop_completion \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-synchronous-idle-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              live_pending_advance_rejects_idle_resume_and_reentrant_publication \
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
            queued_advance_symbol=qemu_plugin_advance_time_ns
            callback_entry=live-all-idle
            timer_bottom_halves=before-normal-main-loop-completion
            pending_advance_suppresses_resume=true
            still_idle_completion_rearms_idle_callback=true
            callback_registration_requires_queued_advance=true
            qemu_install_requires_queued_advance=true
            host_time_apis_on_idle_advance_path=forbidden
            RESULT
          '';
        }
      ];
    }
