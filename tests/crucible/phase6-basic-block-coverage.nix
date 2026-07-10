{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.basicBlockCoverage",
  taskIds ? ["T-ADV-10" "T-PLUG-15" "T-PERF-15"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  pluginDoc = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  perfDoc = builtins.readFile ../../docs/rfcs/0010-crucible/25-performance-targets.md;
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  basicBlockGateTest = builtins.readFile ../../crates/crucible/tests/gate_basic_block_coverage.rs;
  protocol = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  pluginCoverage = builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage.rs;
  pluginCoverageTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage/tests.rs;
  pluginRuntimeTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/tests.rs;
  pluginLiveCallbacksTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/live_callbacks/tests.rs;
  qemuCoverage = builtins.readFile ../../crates/crucible-qemu/src/coverage.rs;
  qemuLiveCoverageGate = builtins.readFile ../../crates/crucible-qemu/src/live_coverage_gate.rs;
  qemuLiveCoverageTrace = builtins.readFile ../../crates/crucible-qemu/src/live_coverage_gate/trace.rs;
  qemuLiveCoverageGateCli = builtins.readFile ../../crates/crucible-qemu/examples/crucible-qemu-live-coverage.rs;
  qemuTracePlugin = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  qemuFingerprintPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch;
  qemuSimObserverPatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0033-crucible-sim-observer.patch;
  guestSource = builtins.readFile ./phase6-basic-block-coverage-guest.nix;
  qemuLaunch = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuCoverageTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_basic_block_coverage.rs;
  qemuMappedQuantum = builtins.readFile ../../crates/crucible-qemu/src/mapped_quantum.rs;
  qemuNode = builtins.readFile ../../crates/crucible-qemu/src/node.rs;
  qemuAsyncDriver = builtins.readFile ../../crates/crucible-qemu/src/async_driver.rs;
  mappedQuantumTest = builtins.readFile ../../crates/crucible-qemu/tests/mapped_quantum.rs;
  backendBoundary = builtins.readFile ../../crates/crucible/src/backend.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  session = import ./_crucible-session-source.nix {inherit lib;};
  pluginCoverageGate = builtins.readFile ./phase2-plugin-coverage.nix;
  anyGuestGate = builtins.readFile ./phase2-any-guest.nix;
  eventLogCoverageGate = builtins.readFile ./phase4-event-log-coverage.nix;
  defaultChecks = builtins.readFile ./default.nix;

  rootImage = pkgs.mkDerivation {
    pname = "crucible-loaded-qemu-coverage-root-image";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.qemu-crucible
    ];

    phases = [
      {
        name = "build-empty-qcow2";
        script = ''
          set -eu
          mkdir -p "$out"
          qemu-img create -q -f qcow2 "$out/root.qcow2" 64M
          qemu-img create -q -f qcow2 "$out/overlay.qcow2" 64M
        '';
      }
    ];
  };

  guestImage = import ./phase6-basic-block-coverage-guest.nix {inherit pkgs;};

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

  indexOf = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
    matches =
      builtins.filter (
        index: builtins.substring index needleLen haystack == needle
      )
      indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  sliceFromUntil = content: startNeedle: endNeedle: let
    start = indexOf startNeedle content;
    tailStart = start + builtins.stringLength startNeedle;
    tail = builtins.substring tailStart (builtins.stringLength content - tailStart) content;
    end = indexOf endNeedle tail;
  in
    if start == null
    then ""
    else if end == null
    then startNeedle + tail
    else startNeedle + builtins.substring 0 end tail;

  defaultBasicBlockCoverageBlock =
    sliceFromUntil
    defaultChecks
    "    basicBlockCoverage = greenBeforeAdvance {"
    "    coverageFeedback = greenBeforeAdvance {";

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc [
      {
        label = "T-ADV-10 is complete after loaded-QEMU callback evidence";
        needle = "- [x] **T-ADV-10**";
      }
      {
        label = "T-ADV-10 completion evidence";
        needle = "Completed by `checks.crucible.phase6.basicBlockCoverage`";
      }
      {
        label = "T-ADV-10 records loaded-QEMU equivalence";
        needle = "production loaded-QEMU gate runs an uninstrumented";
      }
      {
        label = "T-ADV-10 records the completed host event-stream handoff";
        needle = "ABI-v2 per-VM";
      }
      {
        label = "ADV-21 TCG exec hook";
        needle = "TCG-exec hook (12 §12.8)";
      }
      {
        label = "any binary no instrumentation";
        needle = "working on any binary with no guest instrumentation";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginDoc [
      {
        label = "T-PLUG-15 is complete";
        needle = "- [x] **T-PLUG-15**";
      }
      {
        label = "plugin coverage opt-in";
        needle = "registration-time\n  opt-in TCG-exec basic-block map";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/25-performance-targets.md" perfDoc [
      {
        label = "T-PERF-15 is complete";
        needle = "- [x] **T-PERF-15**";
      }
      {
        label = "T-PERF-15 records production observation-only evidence";
        needle = "identical execution fingerprint, canonical causal log, and independent";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-plugin-coverage.nix" pluginCoverageGate [
      {
        label = "plugin exact-entry callback gate";
        needle = "qemu_plugin_icount_at_tb_entry";
      }
      {
        label = "plugin fixed-capacity overflow/FIFO gate";
        needle = "assert_coverage_ring_fifo_and_fails_loud_at_fixed_capacity";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-any-guest.nix" anyGuestGate [
      {
        label = "any-guest gate";
        needle = "gate=gate:any-guest";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-event-log-coverage.nix" eventLogCoverageGate [
      {
        label = "event-log coverage gate";
        needle = "ObservableEventPayload::CoverageBlock";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "coverage config";
        needle = "pub struct BasicBlockCoverageConfig";
      }
      {
        label = "off mode";
        needle = "BasicBlockCoverageMode::Off";
      }
      {
        label = "registration plan";
        needle = "pub fn registration_plan(";
      }
      {
        label = "register TCG exec plan";
        needle = "RegisterTcgExec";
      }
      {
        label = "disabled plan before validation";
        needle = "if self.mode == BasicBlockCoverageMode::Off";
      }
      {
        label = "engine off path has no consumer";
        needle = "has_no_engine_hot_path_consumer";
      }
      {
        label = "no fingerprint effect";
        needle = "pub const fn affects_execution_fingerprint";
      }
      {
        label = "no guest instrumentation";
        needle = "pub const fn requires_guest_instrumentation";
      }
      {
        label = "TCG exec block";
        needle = "pub struct TcgExecBasicBlock";
      }
      {
        label = "consumer token";
        needle = "pub struct BasicBlockCoverageConsumer";
      }
      {
        label = "consumer path";
        needle = "pub fn consume_tcg_exec_block(";
      }
      {
        label = "coverage block event";
        needle = "ObservableEvent::coverage_block";
      }
      {
        label = "basic block map fold";
        needle = "pub fn basic_block_coverage_map_index";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocol [
      {
        label = "protocol coverage observation";
        needle = "pub struct PluginBasicBlockCoverageObservation";
      }
      {
        label = "protocol coverage constructor";
        needle = "pub const fn new(\n        current_icount: u64";
      }
      {
        label = "protocol coverage block length validation";
        needle = "PluginBasicBlockCoverageObservationError::InvalidBlockLength";
      }
      {
        label = "protocol coverage map index";
        needle = "pub const fn map_index(self) -> u64";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/coverage.rs" pluginCoverage [
      {
        label = "plugin callback bridge";
        needle = "pub fn handle_coverage_exec_callback<S>(";
      }
      {
        label = "plugin protocol conversion";
        needle = "pub fn to_protocol_observation(";
      }
      {
        label = "plugin protocol payload constructor";
        needle = "PluginBasicBlockCoverageObservation::new";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/coverage/tests.rs" pluginCoverageTests [
      {
        label = "plugin protocol export gate";
        needle = "coverage_exec_callback_exports_protocol_basic_block_observation";
      }
      {
        label = "coverage callback teardown lifecycle test";
        needle = "coverage_owner_unpublishes_callbacks_before_state_is_freed_and_can_reinstall";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-qemu-plugin/src/coverage.rs" pluginCoverage [
      {
        label = "test-local engine bridge";
        needle = "consume_tcg_exec_block(crucible::TcgExecBasicBlock::new";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/tests.rs" pluginRuntimeTests [
      {
        label = "shared shutdown worker callback drain";
        needle = "shared_shutdown_worker_defers_done_and_clean_qemu_shutdown_until_callback_drain";
      }
      {
        label = "Quit/shared teardown race single-shot proof";
        needle = "quit_selected_first_keeps_receiver_live_for_admitted_callback_shutdown_signal";
      }
      {
        label = "shared shutdown and Quit ordering keeps the reader connected";
        needle = "shared_selected_first_keeps_receiver_live_for_subsequent_quit_delivery";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/live_callbacks/tests.rs" pluginLiveCallbacksTests [
      {
        label = "busy exact-ceiling shared shutdown callback";
        needle = "busy_at_ceiling_publish_callback_signals_shared_shutdown_without_publication";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/coverage.rs" qemuCoverage [
      {
        label = "QEMU bridge type";
        needle = "pub struct QemuBasicBlockCoverageBridge";
      }
      {
        label = "QEMU protocol consumer";
        needle = "pub fn consume_plugin_observation(";
      }
      {
        label = "QEMU bridge uses engine consumer";
        needle = "consume_tcg_exec_block(TcgExecBasicBlock::new";
      }
      {
        label = "QEMU bridge validates plugin map index";
        needle = "PluginMapIndexMismatch";
      }
      {
        label = "QEMU coverage fingerprint run descriptor";
        needle = "pub struct QemuCoverageFingerprintRun";
      }
      {
        label = "coverage on/off fingerprint comparison";
        needle = "pub fn compare_coverage_opt_in_fingerprint_streams";
      }
      {
        label = "single VM fingerprint comparison";
        needle = "compare_single_vm_fingerprint_streams(";
      }
      {
        label = "coverage off run requirement";
        needle = "first run must have coverage=off";
      }
      {
        label = "coverage on run requirement";
        needle = "second run must have coverage=on";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/launch.rs" qemuLaunch [
      {
        label = "plugin whitebox accessor";
        needle = "pub const fn whitebox(&self) -> QemuLaunchPluginSwitch";
      }
      {
        label = "plugin coverage accessor";
        needle = "pub const fn coverage(&self) -> QemuLaunchPluginSwitch";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "QEMU coverage bridge export";
        needle = "QemuBasicBlockCoverageBridge";
      }
      {
        label = "QEMU coverage fingerprint comparison export";
        needle = "compare_coverage_opt_in_fingerprint_streams";
      }
      {
        label = "loaded-QEMU coverage runner export";
        needle = "run_loaded_qemu_coverage_gate";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/live_coverage_gate.rs" qemuLiveCoverageGate [
      {
        label = "production loaded-QEMU off/on runner";
        needle = "pub fn run_loaded_qemu_coverage_gate(";
      }
      {
        label = "real fixed-descriptor QEMU spawn";
        needle = "spawn_qemu_child_with_fds_in_directory(";
      }
      {
        label = "real host/plugin setup";
        needle = "complete_qemu_host_plugin_setup(";
      }
      {
        label = "real shared-memory coverage drain";
        needle = "drain live coverage observations";
      }
      {
        label = "coverage-on observation requirement";
        needle = "LoadedQemuCoverageGateError::CoverageOnEmpty";
      }
      {
        label = "standalone-guest coverage attribution requirement";
        needle = "LoadedQemuCoverageGateError::CoverageOnGuestUnattributed";
      }
      {
        label = "real off/on fingerprint equivalence";
        needle = "off.fingerprint != on.fingerprint";
      }
      {
        label = "real unified event-log admission";
        needle = "record_loaded_run_event_log(mode, config.horizon_icount, observations)?";
      }
      {
        label = "real canonical event-log equivalence";
        needle = "compare_event_log_determinism(&off.event_log_entries, &on.event_log_entries)";
      }
      {
        label = "independent full-state fingerprint equivalence";
        needle = "off.trace_sample != on.trace_sample";
      }
      {
        label = "independent trace plugin launch";
        needle = ".with_observation_plugin(trace_argument)";
      }
      {
        label = "exact instruction-count boundary";
        needle = "completed_icount != config.horizon_icount";
      }
      {
        label = "busy-boundary mapped shared shutdown trigger";
        needle = ".request_plugin_shutdown()";
      }
      {
        label = "busy-boundary QEMU wake";
        needle = ".signal_plugin_wake()";
      }
      {
        label = "coverage-off shared and coverage-on Quit trigger split";
        needle = "QemuLaunchPluginSwitch::Off => LoadedTeardownTrigger::SharedShutdown";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/live_coverage_gate/trace.rs" qemuLiveCoverageTrace [
      {
        label = "independent trace plugin arguments";
        needle = "extended=on,mem_events=on,post_boundary=on,required_pc=";
      }
      {
        label = "independent trace completeness validation";
        needle = "validate_trace_sample(&sample, config, mode)?";
      }
      {
        label = "full fingerprint component requirement";
        needle = ''"extended_hash",'';
      }
      {
        label = "current serialized device-state hash requirement";
        needle = ''"device_state_hash",'';
      }
      {
        label = "serialized device-state byte coverage requirement";
        needle = ''"device_state_bytes"'';
      }
      {
        label = "serialized device-state status requirement";
        needle = ''"device_state_status"'';
      }
      {
        label = "per-instruction guest architectural trajectory requirement";
        needle = ''"trajectory_hash",'';
      }
      {
        label = "guest trajectory begins at the proven post-I/O boundary";
        needle = ".checked_sub(required_pc_first_retired)";
      }
      {
        label = "known post-I/O guest PC requirement";
        needle = "the standalone guest did not reach its known post-I/O basic block";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-trace-plugin.c" qemuTracePlugin [
      {
        label = "per-instruction register trajectory begins after guest entry";
        needle = "post_boundary_samples && required_pc_seen";
      }
      {
        label = "trace hashes writable guest RAM instead of firmware or device RAM";
        needle = "qemu_plugin_crucible_guest_ram_hash(&ram_bytes)";
      }
      {
        label = "trace fingerprints current non-RAM device state";
        needle = "qemu_plugin_crucible_device_state_hash(";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch" qemuFingerprintPatch [
      {
        label = "writable guest-RAM fingerprint API";
        needle = "qemu_plugin_crucible_guest_ram_hash";
      }
      {
        label = "non-RAM VMState fingerprint API";
        needle = "qemu_plugin_crucible_device_state_hash";
      }
      {
        label = "guest-RAM fingerprint excludes ROM";
        needle = "memory_region_is_rom(block->mr)";
      }
      {
        label = "guest-RAM fingerprint excludes device RAM";
        needle = "memory_region_is_ram_device(block->mr)";
      }
      {
        label = "multiboot kernel page padding is initialized before guest exposure";
        needle = "memset((char *)mbs.mb_buf + mb_kernel_size, 0,";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0033-crucible-sim-observer.patch" qemuSimObserverPatch [
      {
        label = "independent post-execution observer API";
        needle = "qemu_plugin_register_sim_shmem_observer_cb";
      }
      {
        label = "observer shares the post-execution icount publication boundary";
        needle = "crucible_observe_icount_cb(current_icount, crucible_sim_observer_userdata)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/examples/crucible-qemu-live-coverage.rs" qemuLiveCoverageGateCli [
      {
        label = "loaded-QEMU runner invocation";
        needle = "run_loaded_qemu_coverage_gate(&config)";
      }
      {
        label = "uninstrumented guest evidence";
        needle = "guest_instrumentation=none";
      }
      {
        label = "post-I/O guest execution evidence";
        needle = "guest_post_io_reached=true";
      }
      {
        label = "live callback evidence";
        needle = "loaded_qemu_callback_evidence=present";
      }
      {
        label = "run control silence evidence";
        needle = ''"run_control_silent={}", report.run_control_silent'';
      }
      {
        label = "plugin Quit consumption evidence";
        needle = ''"plugin_quit_consumed={}", report.plugin_quit_consumed'';
      }
      {
        label = "shared shutdown consumption evidence";
        needle = ''"shared_shutdown_consumed={}",'';
      }
      {
        label = "natural orderly child exit evidence";
        needle = ''"orderly_child_exit={}", report.orderly_child_exit'';
      }
      {
        label = "live fingerprint evidence";
        needle = "coverage_on_off_fingerprint_match=true";
      }
      {
        label = "canonical event-log evidence";
        needle = "canonical_event_log_match=true";
      }
      {
        label = "independent full-state fingerprint evidence";
        needle = "independent_trace_fingerprint_match=true";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-basic-block-coverage-guest.nix" guestSource [
      {
        label = "standalone Multiboot guest";
        needle = ".long 0x1badb002";
      }
      {
        label = "guest has no Crucible cooperation";
        needle = "guest_interface=none";
      }
      {
        label = "guest RX and RW segment separation";
        needle = "text PT_LOAD FLAGS(5)";
      }
      {
        label = "guest exercises deterministic device I/O";
        needle = "outb %al, $0x80";
      }
      {
        label = "guest exposes a fixed post-I/O translation block";
        needle = ". = 0x00100800;";
      }
      {
        label = "guest symbol table is explicitly removed";
        needle = ''strip --strip-all "$out/coverage-guest.elf"'';
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/mapped_quantum.rs" qemuMappedQuantum [
      {
        label = "quantum-boundary coverage drain";
        needle = "fn drain_coverage_at_quantum_boundary(";
      }
      {
        label = "coverage transport boundary drain";
        needle = "fn drain_observable_events(&mut self)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {
        label = "unified event-log coverage admission";
        needle = "pub fn advance_to_ceiling_with_event_log(";
      }
      {
        label = "generic QEMU backend coverage drain test";
        needle = "qemu_node_generic_backend_drains_coverage_without_a_local_side_record";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {
        label = "parallel QEMU-local coverage collection";
        needle = "pending_observable_events";
      }
      {
        label = "coverage carried in the QEMU async report";
        needle = "coverage_events";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-qemu/src/async_driver.rs" qemuAsyncDriver [
      {
        label = "coverage carried in the QEMU async completion";
        needle = "coverage_events";
      }
    ]
    ++ failuresFor "crates/crucible/src/backend.rs" backendBoundary [
      {
        label = "generic backend observation drain hook";
        needle = "fn drain_observable_events(&mut self)";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "canonical scheduler observation append";
        needle = "append_backend_observable_events(observations)";
      }
      {
        label = "shutdown returns final canonical entries to the session";
        needle = "entries.extend(loop_result?)";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "session canonical coverage publication test";
        needle = "actor_publishes_backend_coverage_from_the_canonical_event_log";
      }
      {
        label = "session final coverage publication test";
        needle = "actor_publishes_final_backend_coverage_before_shutdown_completes";
      }
      {
        label = "session final coverage dense-sequence rejection test";
        needle = "engine_rejects_non_dense_final_shutdown_entries";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/mapped_quantum.rs" mappedQuantumTest [
      {
        label = "mapped coverage handoff test";
        needle = "mapped_quantum_drains_coverage_into_the_unified_event_log";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/gate_basic_block_coverage.rs" qemuCoverageTest [
      {
        label = "QEMU protocol consumption gate";
        needle = "gate_basic_block_coverage_consumes_plugin_protocol_observation";
      }
      {
        label = "QEMU coverage fingerprint gate";
        needle = "gate_basic_block_coverage_compares_coverage_on_off_fingerprint_streams";
      }
      {
        label = "coverage off launch arg";
        needle = "coverage=off";
      }
      {
        label = "coverage on launch arg";
        needle = "coverage=on";
      }
      {
        label = "fingerprint report assertion";
        needle = "report.matching_final_fingerprint";
      }
      {
        label = "plugin protocol observation";
        needle = "PluginBasicBlockCoverageObservation::new";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "config exported";
        needle = "BasicBlockCoverageConfig";
      }
      {
        label = "consumer exported";
        needle = "BasicBlockCoverageConsumer";
      }
      {
        label = "TCG block exported";
        needle = "TcgExecBasicBlock";
      }
      {
        label = "map fold exported";
        needle = "basic_block_coverage_map_index";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_basic_block_coverage.rs" basicBlockGateTest [
      {
        label = "registration opt-in gate";
        needle = "gate_basic_block_coverage_is_registration_time_opt_in";
      }
      {
        label = "consumer gate";
        needle = "gate_basic_block_coverage_consumes_tcg_exec_blocks_without_guest_instrumentation";
      }
      {
        label = "fingerprint effect gate";
        needle = "gate_basic_block_coverage_has_zero_fingerprint_effect";
      }
      {
        label = "execution fingerprint assertion";
        needle = "assert_eq!(off_fingerprint, on_fingerprint);";
      }
      {
        label = "disabled callback assertion";
        needle = "CallbackWhileDisabled";
      }
      {
        label = "engine coverage request assertion";
        needle = "requests_tcg_exec_coverage";
      }
      {
        label = "engine no-consumer assertion";
        needle = "has_no_engine_hot_path_consumer";
      }
      {
        label = "external execution trace assertion";
        needle = "BlackBoxObservationSource::ExternalExecutionTrace";
      }
      {
        label = "determinism comparison assertion";
        needle = "compare_event_log_determinism(&baseline, &with_coverage).passes()";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_basic_block_coverage.rs" basicBlockGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix basicBlockCoverage block" defaultBasicBlockCoverageBlock [
      {
        label = "phase6 basic block coverage green wrapper";
        needle = "basicBlockCoverage = greenBeforeAdvance";
      }
      {
        label = "phase6 basic block coverage import";
        needle = "gate = import ./phase6-basic-block-coverage.nix";
      }
      {
        label = "phase6 basic block coverage attr path";
        needle = "checks.crucible.phase6.basicBlockCoverage";
      }
      {
        label = "phase6 basic block coverage completed task ids";
        needle = ''taskIds = ["T-ADV-10" "T-PLUG-15" "T-PERF-15"]'';
      }
      {
        label = "phase6 basic block coverage has no open task ids";
        needle = "openTaskIds = [];";
      }
      {
        label = "phase2 single VM fingerprint raw dependency";
        needle = "\n          phase2.gates.singleVmFingerprint.rawGate\n";
      }
      {
        label = "phase2 any-guest raw dependency";
        needle = "\n          phase2.gates.anyGuest.rawGate\n";
      }
      {
        label = "phase2 plugin coverage dependency";
        needle = "\n          phase2.qemuPluginCoverage\n";
      }
      {
        label = "phase4 e2e determinism raw dependency";
        needle = "\n          phase4.gates.e2eDeterminism.rawGate\n";
      }
      {
        label = "phase4 event log coverage dependency";
        needle = "\n          phase4.eventLogCoverage\n";
      }
      {
        label = "phase6 state-space search raw dependency";
        needle = "\n          phase6.stateSpaceSearch.rawGate\n";
      }
      {
        label = "phase6 search reductions raw dependency";
        needle = "\n          phase6.searchReductions.rawGate\n";
      }
      {
        label = "phase2 single VM fingerprint green dependency";
        needle = "\n        phase2.gates.singleVmFingerprint\n";
      }
      {
        label = "phase2 any-guest green dependency";
        needle = "\n        phase2.gates.anyGuest\n";
      }
      {
        label = "phase4 e2e determinism green dependency";
        needle = "\n        phase4.gates.e2eDeterminism\n";
      }
      {
        label = "phase6 state-space search green dependency";
        needle = "\n        phase6.stateSpaceSearch\n";
      }
      {
        label = "phase6 search reductions green dependency";
        needle = "\n        phase6.searchReductions\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 basic block coverage check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-basic-block-coverage";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.crucible-qemu-plugin
        pkgs.crucible-qemu-trace-plugin
        pkgs.qemu-crucible
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            set -eu
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-basic-block-coverage";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-basic-block-coverage-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_basic_block_coverage \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-basic-block-coverage-plugin-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              coverage_exec_callback_exports_protocol_basic_block_observation \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-basic-block-coverage-plugin-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              runtime:: \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-basic-block-coverage-qemu-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              live_coverage_gate:: \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-basic-block-coverage-qemu-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test gate_basic_block_coverage \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-basic-block-coverage-qemu-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test mapped_quantum \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-basic-block-coverage-session-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-session \
              actor_publishes_ \
              -- --test-threads=1

            off_run="$TMPDIR/loaded-qemu-coverage-off"
            on_run="$TMPDIR/loaded-qemu-coverage-on"
            readelf -h ${guestImage}/coverage-guest.elf \
              | grep -Eq 'Class:[[:space:]]+ELF32'
            readelf -W -l ${guestImage}/coverage-guest.elf \
              | grep -Eq 'LOAD.* R E '
            readelf -W -l ${guestImage}/coverage-guest.elf \
              | grep -Eq 'LOAD.* RW '
            if readelf -W -S ${guestImage}/coverage-guest.elf | grep -q '[.]symtab'; then
              echo 'standalone coverage guest retained a symbol table after fixup' >&2
              exit 1
            fi
            od -An -tx4 -N8192 ${guestImage}/coverage-guest.elf \
              | grep -q '1badb002'
            grep -q '^guest_interface=none$' ${guestImage}/evidence.env
            grep -q '^guest_instrumentation=none$' ${guestImage}/evidence.env
            grep -q '^guest_device_io=vga-mmio-and-port-80$' ${guestImage}/evidence.env
            mkdir -p "$off_run" "$on_run"
            cp ${rootImage}/overlay.qcow2 "$off_run/crucible-root-overlay.qcow2"
            cp ${rootImage}/overlay.qcow2 "$on_run/crucible-root-overlay.qcow2"
            chmod u+w \
              "$off_run/crucible-root-overlay.qcow2" \
              "$on_run/crucible-root-overlay.qcow2"
            timeout -k 15 180 cargo run \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-loaded-qemu-coverage-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --example crucible-qemu-live-coverage \
              -- \
              ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
              ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
              ${pkgs.crucible-qemu-trace-plugin}/lib/qemu/plugins/crucible-qemu-trace-plugin.so \
              ${guestImage}/coverage-guest.elf \
              ${rootImage}/root.qcow2 \
              "$off_run" \
              "$on_run" \
              > "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^PASS$' "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^loaded_qemu_callback_evidence=present$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^guest_instrumentation=none$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^guest_post_io_reached=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^coverage_on_off_fingerprint_match=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^canonical_event_log_match=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -Eq '^canonical_event_log_fingerprint=[0-9a-f]{64}$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^independent_trace_fingerprint_match=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^run_control_silent=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^plugin_quit_consumed=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^shared_shutdown_consumed=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^orderly_child_exit=true$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -q '^trace_components=instruction-stream,all-vcpu-registers,rr-cursor,ram,device-io$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -Eq '^coverage_observation_count=[1-9][0-9]*$' \
              "$TMPDIR/loaded-qemu-coverage.result"
            grep -Eq '^guest_coverage_observation_count=[1-9][0-9]*$' \
              "$TMPDIR/loaded-qemu-coverage.result"
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cp "$TMPDIR/loaded-qemu-coverage.result" "$out/loaded-qemu-coverage.result"
            cp "$TMPDIR/loaded-qemu-coverage-off/independent-fingerprint.jsonl" \
              "$out/coverage-off-independent-fingerprint.jsonl"
            cp "$TMPDIR/loaded-qemu-coverage-on/independent-fingerprint.jsonl" \
              "$out/coverage-on-independent-fingerprint.jsonl"
            cp ${guestImage}/evidence.env "$out/guest-evidence.env"
            readelf -W -h -l -S ${guestImage}/coverage-guest.elf \
              > "$out/guest-elf-inspection.txt"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=pass
            gate=gate:basic-block-coverage
            hook=live-tcg-exec-to-shmem-observation
            loaded_qemu_callback_evidence=present
            loaded_qemu_guest=uninstrumented-standalone-multiboot-elf
            loaded_qemu_fingerprint_equivalence=coverage-off-equals-coverage-on
            loaded_qemu_independent_fingerprint=instruction-stream,all-vcpu-registers,rr-cursor,ram,device-io
            loaded_qemu_trajectory_fingerprint=guest-per-instruction-register-memory-io-plus-post-boundary-state
            host_observation_handoff=abi-v2-per-vm-spsc-to-unified-event-log
            registration=opt-in
            fingerprint_effect=none
            canonical_event_log_effect=none
            teardown_proof=coverage-off-shared-shutdown-busy-boundary,coverage-on-control-quit
            rust_test=crucible::gate_basic_block_coverage
            qemu_bridge_test=crucible-qemu::gate_basic_block_coverage
            RESULT
          '';
        }
      ];
    }
