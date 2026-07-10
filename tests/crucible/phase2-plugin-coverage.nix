{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginCoverage",
  taskIds ? ["T-PLUG-15"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginArgs = builtins.readFile ../../crates/crucible-qemu-plugin/src/args.rs;
  pluginCoverage = builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage.rs;
  pluginCoverageTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage/tests.rs;
  liveCoverageGate = builtins.readFile ./phase6-basic-block-coverage.nix;
  coverageAbiModel = builtins.readFile ./phase2-plugin-coverage-abi.c;
  qemuCoveragePatch = builtins.readFile ../../pkgs/emulation/qemu-patches/0014-crucible-plugin-tcg-exec-cb.patch;
  pluginRegistration = builtins.readFile ../../crates/crucible-qemu-plugin/src/registration.rs;
  pluginRegistrationTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/registration/tests.rs;
  pluginRuntime = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime.rs;
  pluginRuntimeTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/runtime/tests.rs;
  shmemLib = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-shmem/src/lib.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/ring_coverage.rs)
  ];
  shmemSpscTest = builtins.readFile ../../crates/crucible-shmem/tests/gate_layer1_injection.rs;
  mappedSetupRegion = builtins.readFile ../../crates/crucible-shmem/src/mapped_setup_region.rs;
  qemuMappedQuantum = builtins.readFile ../../crates/crucible-qemu/src/mapped_quantum.rs;
  qemuNode = builtins.readFile ../../crates/crucible-qemu/src/node.rs;
  mappedQuantumTest = builtins.readFile ../../crates/crucible-qemu/tests/mapped_quantum.rs;
  backendBoundary = builtins.readFile ../../crates/crucible/src/backend.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  session = import ./_crucible-session-source.nix {inherit lib;};
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  patchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  advancedSpec = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
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

  forbiddenCallbackApis = [
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
    "Mutex"
    "RwLock"
    ".lock()"
    "libc::"
    "eprintln!"
    "println!"
    "format!"
  ];

  forbiddenCallbackFailures =
    lib.concatMap (
      api:
        lib.optionals (hasInfix api pluginCoverage) [
          "crates/crucible-qemu-plugin/src/coverage.rs: forbidden host-time, entropy, lock, allocation, or diagnostic-I/O API in coverage callback path: `${api}`"
        ]
    )
    forbiddenCallbackApis;

  mutatingIcountFailure = lib.optionals (hasInfix "state.apis.icount_raw" pluginCoverage) [
    "crates/crucible-qemu-plugin/src/coverage.rs: execution callback must not call the state-mutating raw-icount API"
  ];

  misleadingTestEvidenceFailures =
    lib.concatMap (
      needle:
        lib.optionals (hasInfix needle pluginCoverage) [
          "crates/crucible-qemu-plugin/src/coverage.rs: callback stub evidence must use callback-model or ABI-model naming, not `${needle}`"
        ]
    ) [
      "fn live_test_"
      "coverage_live_"
      "capture_real"
    ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-15 is complete after the loaded-QEMU fingerprint run";
        needle = "- [x] **T-PLUG-15**";
      }
      {
        label = "T-PLUG-15 records the loaded-QEMU equivalence evidence";
        needle = "independent instruction/register/RR-cursor/writable-RAM/device-I/O trajectory";
      }
      {
        label = "T-PLUG-15 records the ABI-v2 host observation handoff";
        needle = "dedicated per-VM SPSC ring";
      }
      {
        label = "coverage hook wording";
        needle = "Implement the optional coverage hook";
      }
      {
        label = "zero cost wording";
        needle = "zero cost when off";
      }
      {
        label = "observational wording";
        needle = "emit coverage as observational output";
      }
    ]
    ++ failuresFor "tests/crucible/phase6-basic-block-coverage.nix" liveCoverageGate [
      {
        label = "production loaded-QEMU coverage proof";
        needle = "loaded_qemu_fingerprint_equivalence=coverage-off-equals-coverage-on";
      }
      {
        label = "production loaded-QEMU canonical-log proof";
        needle = "canonical_event_log_effect=none";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" patchSpec [
      {
        label = "TCG-exec callback export spec";
        needle = "qemu_plugin_register_tcg_exec_cb";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedSpec [
      {
        label = "basic-block coverage spec";
        needle = "TCG-execution hook";
      }
      {
        label = "coverage feedback only spec";
        needle = "Coverage MUST feed the search and fuzzer as feedback only";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "coverage module exported";
        needle = "pub mod coverage;";
      }
      {
        label = "coverage state exported";
        needle = "PluginCoverage";
      }
      {
        label = "coverage map exported";
        needle = "CoverageMap";
      }
      {
        label = "coverage registration plan exported";
        needle = "CoverageRegistrationPlan";
      }
      {
        label = "coverage callback token exported";
        needle = "CoverageCallback";
      }
      {
        label = "coverage sink exported";
        needle = "CoverageSink";
      }
      {
        label = "coverage callback exported";
        needle = "handle_coverage_exec_callback";
      }
      {
        label = "stock TB translation symbol exported";
        needle = "QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL";
      }
      {
        label = "stock TB execution symbol exported";
        needle = "QEMU_PLUGIN_REGISTER_VCPU_TB_EXEC_CB_SYMBOL";
      }
      {
        label = "exact TB-entry icount symbol exported";
        needle = "QEMU_PLUGIN_ICOUNT_AT_TB_ENTRY_SYMBOL";
      }
      {
        label = "stock flush callback symbol exported";
        needle = "QEMU_PLUGIN_REGISTER_FLUSH_CB_SYMBOL";
      }
    ]
    ++ failuresFor "crates/crucible-shmem split modules" shmemLib [
      {
        label = "coverage transport ABI version";
        needle = "pub const ABI_VERSION: u32 = 2;";
      }
      {
        label = "coverage queue bounded by map cardinality";
        needle = "pub const COVERAGE_QUEUE_CAPACITY: u32 = 65_536;";
      }
      {
        label = "compact coverage ABI entry";
        needle = "pub struct CoverageEntry";
      }
      {
        label = "release-published coverage queue";
        needle = "pub fn enqueue_coverage(";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/mapped_setup_region.rs" mappedSetupRegion [
      {
        label = "validated per-VM mapped coverage ring";
        needle = "pub fn coverage_ring_mut(";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime.rs" pluginRuntime [
      {
        label = "plugin runtime binds the mapped coverage producer";
        needle = "LiveCoverageShmemProducer::from_raw_parts";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/mapped_quantum.rs" qemuMappedQuantum [
      {
        label = "host quantum-boundary coverage drain";
        needle = "fn drain_coverage_at_quantum_boundary(";
      }
      {
        label = "host boundary drain implementation";
        needle = "fn drain_observable_events(&mut self)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {
        label = "coverage-enabled unified event-log API";
        needle = "pub fn advance_to_ceiling_with_event_log(";
      }
      {
        label = "direct unified-log admission";
        needle = "append_observable_events(events)";
      }
      {
        label = "generic QEMU backend drain has no local side record";
        needle = "qemu_node_generic_backend_drains_coverage_without_a_local_side_record";
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
        label = "backend observations appended to canonical scheduler log";
        needle = "append_backend_observable_events(observations)";
      }
      {
        label = "shutdown returns final canonical entries to the session";
        needle = "entries.extend(loop_result?)";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" session [
      {
        label = "session actor publishes canonical backend coverage";
        needle = "actor_publishes_backend_coverage_from_the_canonical_event_log";
      }
      {
        label = "session actor publishes final teardown coverage";
        needle = "actor_publishes_final_backend_coverage_before_shutdown_completes";
      }
      {
        label = "session rejects non-dense final teardown entries";
        needle = "engine_rejects_non_dense_final_shutdown_entries";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/mapped_quantum.rs" mappedQuantumTest [
      {
        label = "mapped plugin-to-host unified event-log test";
        needle = "mapped_quantum_drains_coverage_into_the_unified_event_log";
      }
      {
        label = "corrupt or duplicate coverage rejection test";
        needle = "mapped_quantum_rejects_duplicate_novelty_and_future_icount_loudly";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/args.rs" pluginArgs [
      {
        label = "coverage launch argument key";
        needle = "PLUGIN_ARG_COVERAGE";
      }
      {
        label = "coverage switch parsed from args";
        needle = "let coverage = parse_optional_switch";
      }
      {
        label = "coverage switch accessor";
        needle = "pub const fn coverage(&self) -> PluginSwitch";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/coverage split modules" pluginCoverage [
      {
        label = "coverage state";
        needle = "pub struct PluginCoverage";
      }
      {
        label = "registration plan";
        needle = "pub fn registration_plan";
      }
      {
        label = "off-mode disabled plan";
        needle = "CoverageRegistrationPlan::Disabled";
      }
      {
        label = "off-mode checked before validation";
        needle = "if !self.mode.is_on()";
      }
      {
        label = "hot path zero overhead method";
        needle = "hot_path_has_zero_coverage_overhead";
      }
      {
        label = "callback proof token";
        needle = "pub struct CoverageCallback";
      }
      {
        label = "enabled plan callback token";
        needle = "pub const fn require_callback";
      }
      {
        label = "stock TB translation callback capability";
        needle = "QEMU_PLUGIN_REGISTER_VCPU_TB_TRANS_CB_SYMBOL";
      }
      {
        label = "stock TB translation symbol spelling";
        needle = "\"qemu_plugin_register_vcpu_tb_trans_cb\"";
      }
      {
        label = "stock TB execution symbol spelling";
        needle = "\"qemu_plugin_register_vcpu_tb_exec_cb\"";
      }
      {
        label = "live coverage owner";
        needle = "pub(crate) struct LiveBasicBlockCoverage";
      }
      {
        label = "lock-free callback-state publication";
        needle = "static LIVE_COVERAGE_STATE: AtomicPtr<LiveCoverageInner>";
      }
      {
        label = "translation callback reads guest PC";
        needle = "let guest_pc = (state.apis.tb_vaddr)(tb.cast_const());";
      }
      {
        label = "translation callback derives block length";
        needle = "checked_add((state.apis.insn_size)(insn.cast_const()))";
      }
      {
        label = "translation callback installs TB execution callback";
        needle = "Some(live_coverage_tb_exec)";
      }
      {
        label = "execution callback observes exact TB-entry icount";
        needle = "(state.apis.icount_at_tb_entry)(";
      }
      {
        label = "flush callback registered before translation callbacks";
        needle = "(apis.register_flush_cb)(plugin_id, live_coverage_flush);";
      }
      {
        label = "flush callback reclaims translation metadata";
        needle = "state.translated_blocks.clear();";
      }
      {
        label = "live sink coalesces repeat coverage before the host handoff";
        needle = "if !observation.was_new()";
      }
      {
        label = "live sink fails instead of silently evicting novel coverage";
        needle = ".enqueue_coverage(entries, entry)";
      }
      {
        label = "callback failures terminate instead of degrading coverage";
        needle = "fn abort_live_coverage_callback(error: CoverageError) -> !";
      }
      {
        label = "live callback failures use allocation-free static errors";
        needle = "CoverageSinkError::from_static";
      }
      {
        label = "coverage map";
        needle = "pub struct CoverageMap";
      }
      {
        label = "fixed map default";
        needle = "DEFAULT_COVERAGE_MAP_ENTRIES";
      }
      {
        label = "basic block event";
        needle = "pub struct CoverageBlockEvent";
      }
      {
        label = "guest pc";
        needle = "guest_pc";
      }
      {
        label = "deterministic pc fold";
        needle = "pub fn fold_basic_block_pc";
      }
      {
        label = "map update";
        needle = "map.mark(map_index)";
      }
      {
        label = "saturating counter";
        needle = "saturating_add";
      }
      {
        label = "coverage observation";
        needle = "pub struct CoverageObservation";
      }
      {
        label = "coverage sink";
        needle = "pub trait CoverageSink";
      }
      {
        label = "observational record method";
        needle = "record_coverage";
      }
      {
        label = "safe coverage callback body";
        needle = "pub fn handle_coverage_exec_callback";
      }
      {
        label = "callback avoids deterministic-state side effects";
        needle = "No scheduler, virtual-time, injection state";
      }
      {
        label = "disabled callback failure";
        needle = "CallbackWhileDisabled";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/coverage/tests.rs" pluginCoverageTests [
      {
        label = "callback ABI model test";
        needle = "coverage_callback_abi_model_captures_block_pc_length_and_exact_entry_icount";
      }
      {
        label = "flush and retranslation model test";
        needle = "coverage_flush_reclaims_metadata_before_retranslation";
      }
      {
        label = "novel coverage output retention test";
        needle = "live_coverage_sink_retains_each_novelty_without_silent_eviction";
      }
      {
        label = "coverage teardown unpublishes callback state and permits reinstall";
        needle = "coverage_owner_unpublishes_callbacks_before_state_is_freed_and_can_reinstall";
      }
      {
        label = "off-mode test";
        needle = "coverage_registration_off_mode_installs_no_callback_and_ignores_map_config";
      }
      {
        label = "on-mode capability test";
        needle = "coverage_registration_on_mode_requires_basic_block_callback_capability";
      }
      {
        label = "basic-block fold test";
        needle = "coverage_exec_callback_folds_basic_block_pc_and_records_observation";
      }
      {
        label = "repeat counter test";
        needle = "coverage_exec_callback_uses_saturating_counters_without_new_signal_on_repeat";
      }
      {
        label = "disabled plan callback token test";
        needle = "coverage_disabled_plan_cannot_build_hot_callback_and_does_not_touch_map";
      }
      {
        label = "map mismatch test";
        needle = "coverage_exec_callback_rejects_wrong_map_size_before_recording";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/gate_layer1_injection.rs" shmemSpscTest [
      {
        label = "fixed cardinality coverage queue full/FIFO proof";
        needle = "assert_coverage_ring_fifo_and_fails_loud_at_fixed_capacity";
      }
      {
        label = "coverage SPSC ordering proof";
        needle = "pub fn dequeue_coverage(";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu-patches/0014-crucible-plugin-tcg-exec-cb.patch" qemuCoveragePatch [
      {
        label = "public exact TB-entry helper";
        needle = "int qemu_plugin_icount_at_tb_entry(uint64_t tb_insns,";
      }
      {
        label = "non-mutating raw-icount observation";
        needle = "int64_t icount_get_raw_observed(void)";
      }
      {
        label = "active RR vCPU selection";
        needle = "CPUState *cpu = current_cpu;";
      }
      {
        label = "active vCPU executed-count observation";
        needle = "executed = icount_get_executed(cpu);";
      }
      {
        label = "exact TB-entry reservation subtraction";
        needle = "*entry_icount = (uint64_t)observed_icount - tb_insns;";
      }
      {
        label = "exact TB-entry helper rejects non-RR execution";
        needle = "!qemu_plugin_crucible_single_threaded_rr()";
      }
      {
        label = "exact TB-entry helper requires an active vCPU callback context";
        needle = "!entry_icount || tb_insns == 0 || !current_cpu ||";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-plugin-coverage-abi.c" coverageAbiModel [
      {
        label = "ABI model names its evidence honestly";
        needle = "This is an ABI-and-arithmetic model microtest";
      }
      {
        label = "first translated-block entry case";
        needle = "check_entry(100, 40, 33, 7, 100)";
      }
      {
        label = "chained translated-block entry case";
        needle = "check_entry(100, 40, 28, 5, 107)";
      }
      {
        label = "post-refill entry case";
        needle = "check_entry(112, 30, 21, 9, 112)";
      }
      {
        label = "round-robin next-vCPU entry case";
        needle = "check_entry(200, 10, 8, 2, 200)";
      }
      {
        label = "non-RR mode rejection case";
        needle = "model_single_threaded_rr = 0;";
      }
      {
        label = "inactive-vCPU callback-context rejection case";
        needle = "model_active_vcpu = 0;";
      }
      {
        label = "non-precise icount rejection case";
        needle = "model_precise_icount = 0;";
      }
      {
        label = "signed icount overflow rejection case";
        needle = "model_committed = INT64_MAX;";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration.rs" pluginRegistration [
      {
        label = "registration consumes parsed coverage switch";
        needle = "PluginCoverage::with_default_map(args.coverage())";
      }
      {
        label = "registration accepts coverage capabilities";
        needle = "coverage_capabilities: CoverageCapabilities";
      }
      {
        label = "registration returns coverage plan";
        needle = "coverage_registration_plan";
      }
      {
        label = "registration returns coverage callback token";
        needle = "coverage_callback";
      }
      {
        label = "registration fails on missing TCG-exec callback";
        needle = "fail_coverage_capability";
      }
      {
        label = "registration installs live owned coverage";
        needle = "register_basic_block_coverage(plugin_id, args.slot(), callback, apis)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/registration/tests.rs" pluginRegistrationTests [
      {
        label = "registration off coverage test";
        needle = "registration_coverage_off_installs_no_callback_without_capability";
      }
      {
        label = "registration on missing capability test";
        needle = "registration_coverage_on_requires_basic_block_callback_capability";
      }
      {
        label = "registration on callback token test";
        needle = "registration_coverage_on_builds_basic_block_callback_token";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime.rs" pluginRuntime [
      {
        label = "pinned runtime owns optional coverage callbacks";
        needle = "coverage: Option<LiveBasicBlockCoverage>";
      }
      {
        label = "runtime coverage registration owner";
        needle = "fn register_basic_block_coverage(";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/runtime/tests.rs" pluginRuntimeTests [
      {
        label = "install ownership callback model test";
        needle = "install_coverage_on_owns_callback_model_registration";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin coverage check";
        needle = "qemuPluginCoverage = import ./phase2-plugin-coverage.nix";
      }
    ]
    ++ forbiddenCallbackFailures
    ++ mutatingIcountFailure
    ++ misleadingTestEvidenceFailures;
in
  if failures != []
  then throw "crucible phase2 plugin coverage check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-coverage";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.glib
        pkgs.pkg-config
        pkgs.qemu-crucible
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
          name = "verify-qemu10-coverage-callback-ordering";
          script = ''
            set -eu
            qemu_source="$TMPDIR/qemu-coverage-ordering-source"
            mkdir -p "$qemu_source"
            tar -xf ${pkgs.qemu-crucible.src} -C "$qemu_source"
            qemu_tree="$qemu_source/qemu-${pkgs.qemu-crucible.version}"

            awk '
              /void qemu_plugin_flush_cb\(void\)/ { in_flush = 1 }
              in_flush && /qht_iter_remove\(&plugin.dyn_cb_arr_ht, free_dyn_cb_arr, NULL\)/ {
                destroyed = NR
              }
              in_flush && /qht_reset\(&plugin.dyn_cb_arr_ht\)/ { reset = NR }
              in_flush && /plugin_cb__simple\(QEMU_PLUGIN_EV_FLUSH\)/ { notified = NR }
              END {
                exit !(destroyed && reset && notified &&
                       destroyed < notified && reset < notified)
              }
            ' "$qemu_tree/plugins/core.c"
            grep -q 'tb_flush() takes care of running the flush in an exclusive context' \
              "$qemu_tree/include/exec/tb-flush.h"
            grep -q 'if (cpu_in_serial_context(cpu))' \
              "$qemu_tree/accel/tcg/tb-maint.c"
            grep -q 'async_safe_run_on_cpu(cpu, do_tb_flush' \
              "$qemu_tree/accel/tcg/tb-maint.c"
            awk '
              /icount_start_insn = gen_tb_start\(db, cflags\)/ { prologue = NR }
              /plugin_enabled = plugin_gen_tb_start\(cpu, db\)/ { plugin = NR }
              END { exit !(prologue && plugin && prologue < plugin) }
            ' "$qemu_tree/accel/tcg/translator.c"
            awk '
              /static TCGOp \*gen_tb_start/ { in_start = 1 }
              in_start && /tcg_gen_sub_i32\(count, count/ { subtract = NR }
              in_start && /tcg_gen_brcondi_i32\(TCG_COND_LT, count, 0/ { budget_exit = NR }
              in_start && /tcg_gen_st16_i32\(count, tcg_env/ { reserve = NR }
              in_start && /return icount_start_insn/ { done = NR; in_start = 0 }
              END {
                exit !(subtract && budget_exit && reserve && done &&
                       subtract < budget_exit && budget_exit < reserve && reserve < done)
              }
            ' "$qemu_tree/accel/tcg/translator.c"
            awk '
              /void plugin_gen_tb_end\(CPUState \*cpu, size_t num_insns\)/ { in_end = 1 }
              in_end && /qemu_plugin_tb_trans_cb\(cpu, ptb\)/ { translate = NR }
              in_end && /plugin_gen_inject\(ptb\)/ { inject = NR }
              in_end && /^}/ { in_end = 0 }
              /case PLUGIN_GEN_FROM_TB:/ { from_tb = NR }
              from_tb && /inject_cb\(/ { callback = NR }
              END {
                exit !(translate && inject && translate < inject &&
                       from_tb && callback && from_tb < callback)
              }
            ' "$qemu_tree/accel/tcg/plugin-gen.c"
            grep -Fq 'return (cpu->icount_budget -' \
              "$qemu_tree/accel/tcg/icount-common.c"
            grep -Fq '(cpu->neg.icount_decr.u16.low + cpu->icount_extra));' \
              "$qemu_tree/accel/tcg/icount-common.c"
            grep -Fq 'cpu->neg.icount_decr.u16.low += insns_left' \
              "$qemu_tree/accel/tcg/translate-all.c"
            awk '
              /current_cpu = cpu;/ { current = NR }
              /r = tcg_cpu_exec\(cpu\);/ { execute = NR }
              execute && /icount_process_data\(cpu\);/ { process = NR }
              END { exit !(current && execute && process && current < execute && execute < process) }
            ' "$qemu_tree/accel/tcg/tcg-accel-ops-rr.c"
            awk '
              /int tcg_cpu_exec\(CPUState \*cpu\)/ { in_exec = 1 }
              in_exec && /cpu_exec_start\(cpu\);/ { start = NR }
              in_exec && /ret = cpu_exec\(cpu\);/ { execute = NR }
              in_exec && /cpu_exec_end\(cpu\);/ { finish = NR }
              in_exec && /^}/ { in_exec = 0 }
              END {
                exit !(start && execute && finish &&
                       start < execute && execute < finish)
              }
            ' "$qemu_tree/accel/tcg/tcg-accel-ops.c"
          '';
        }
        {
          name = "compile-coverage-qemu-abi";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cc -std=c11 -Wall -Wextra -Werror \
              $(pkg-config --cflags glib-2.0) \
              -I${pkgs.qemu-crucible}/include \
              tests/crucible/phase2-plugin-coverage-abi.c \
              -o "$TMPDIR/phase2-plugin-coverage-abi-model"
            "$TMPDIR/phase2-plugin-coverage-abi-model"
          '';
        }
        {
          name = "run-plugin-coverage";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-coverage-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              coverage_ \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-coverage-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-shmem \
              --test gate_abi_conformance \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-coverage-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test mapped_quantum \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-plugin-coverage-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-session \
              actor_publishes_ \
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
            status=pass
            off_mode=disabled-plan-installs-no-tcg-exec-callback
            coverage_signal=guest-pc-folded-into-fixed-map
            callback_api=stock-qemu-tb-translation-execution-and-flush-plus-exact-entry-helper
            callback_test_evidence=rust-callback-model-and-executable-c-abi-arithmetic-model
            qemu10_flush_ordering=dynamic-callback-arrays-destroyed-and-reset-before-plugin-flush-callback
            qemu10_flush_context=serialized-or-async-exclusive
            exact_entry_math=committed-plus-budget-minus-remaining-minus-tb-insns
            exact_entry_edge_evidence=first-chained-post-refill-next-rr-vcpu-model-plus-early-exit-source-order
            live_qemu_proof=checks.crucible.phase6.basicBlockCoverage
            host_observation_handoff=abi-v2-per-vm-spsc-quantum-boundary-unified-event-log
            callback_state=pinned-atomic-singleton-no-locks
            output=bounded-lossless-observation-admitted-to-unified-event-log
            hot_path_when_off=no-registered-callback
            callback_host_time_apis=forbidden
            RESULT
          '';
        }
      ];
    }
