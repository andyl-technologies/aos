{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.basicBlockCoverage",
  taskIds ? ["T-ADV-10"],
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
  trigger = builtins.readFile ../../crates/crucible/src/trigger.rs;
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  basicBlockGateTest = builtins.readFile ../../crates/crucible/tests/gate_basic_block_coverage.rs;
  protocol = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  pluginCoverage = builtins.readFile ../../crates/crucible-qemu-plugin/src/coverage.rs;
  qemuCoverage = builtins.readFile ../../crates/crucible-qemu/src/coverage.rs;
  qemuLaunch = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  qemuCoverageTest = builtins.readFile ../../crates/crucible-qemu/tests/gate_basic_block_coverage.rs;
  pluginCoverageGate = builtins.readFile ./phase2-plugin-coverage.nix;
  anyGuestGate = builtins.readFile ./phase2-any-guest.nix;
  eventLogCoverageGate = builtins.readFile ./phase4-event-log-coverage.nix;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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
    "    gates = {";

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
        label = "T-ADV-10 checked off";
        needle = "- [x] **T-ADV-10**";
      }
      {
        label = "T-ADV-10 completion note";
        needle = "Completed by `checks.crucible.phase6.basicBlockCoverage`";
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
        label = "T-PLUG-15 already complete";
        needle = "- [x] **T-PLUG-15**";
      }
      {
        label = "plugin coverage opt-in";
        needle = "registration-time\n  opt-in TCG-exec basic-block map";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-plugin-coverage.nix" pluginCoverageGate [
      {
        label = "plugin hook gate";
        needle = "qemu_plugin_register_tcg_exec_cb";
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
        label = "plugin protocol export gate";
        needle = "coverage_exec_callback_exports_protocol_basic_block_observation";
      }
      {
        label = "plugin callback bridge";
        needle = "handle_coverage_exec_callback(";
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
    ++ forbiddenFailuresFor "crates/crucible-qemu-plugin/src/coverage.rs" pluginCoverage [
      {
        label = "test-local engine bridge";
        needle = "consume_tcg_exec_block(crucible::TcgExecBasicBlock::new";
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
        label = "phase6 basic block coverage task id";
        needle = ''taskIds = ["T-ADV-10"]'';
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
              --target-dir "$TMPDIR/crucible-basic-block-coverage-qemu-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test gate_basic_block_coverage \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${taskList}
            gate=gate:basic-block-coverage
            hook=tcg-exec
            registration=opt-in
            fingerprint_effect=none
            rust_test=crucible::gate_basic_block_coverage
            qemu_bridge_test=crucible-qemu::gate_basic_block_coverage
            RESULT
          '';
        }
      ];
    }
