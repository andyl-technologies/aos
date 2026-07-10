{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.gates.controlResponsive",
  taskIds ? ["T-HARN-15"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  apiLib = builtins.readFile ../../crates/crucible-api/src/lib.rs;
  apiControl = builtins.readFile ../../crates/crucible-api/src/control_responsive.rs;
  apiGateTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_responsive.rs;
  daemonManifest = builtins.readFile ../../crates/crucible-daemon/Cargo.toml;
  daemonLib = builtins.readFile ../../crates/crucible-daemon/src/lib.rs;
  daemonControl = builtins.readFile ../../crates/crucible-daemon/src/control_responsiveness.rs;
  daemonGateTest = builtins.readFile ../../crates/crucible-daemon/tests/gate_control_responsive.rs;
  sessionGateTest = builtins.readFile ../../crates/crucible-session/tests/gate_control_responsive.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  harnessLib = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateTargetNix = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  protocolSetupFailure = builtins.readFile ./phase2-protocol-setup-failure.nix;
  protocolShutdownEscalation = builtins.readFile ./phase2-protocol-shutdown-escalation.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

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

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-15 checked off";
        needle = "- [x] **T-HARN-15**";
      }
      {
        label = "T-HARN-15 completion note";
        needle = "Completed by `checks.crucible.phase5.gates.controlResponsive`";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/lib.rs" apiLib [
      {
        label = "control-responsive module";
        needle = "pub mod control_responsive;";
      }
      {
        label = "control-responsive exports";
        needle = "validate_control_responsiveness";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/control_responsive.rs" apiControl [
      {
        label = "one quantum bound";
        needle = "pub const CONTROL_RESPONSIVE_QUANTUM_BOUND: u64 = 1;";
      }
      {
        label = "required operations";
        needle = "CONTROL_RESPONSIVE_REQUIRED_OPERATIONS";
      }
      {
        label = "pause coverage";
        needle = "ControlOperationKind::Pause";
      }
      {
        label = "snapshot coverage";
        needle = "ControlOperationKind::Snapshot";
      }
      {
        label = "fork coverage";
        needle = "ControlOperationKind::Fork";
      }
      {
        label = "inject coverage";
        needle = "ControlOperationKind::Inject";
      }
      {
        label = "query coverage";
        needle = "ControlOperationKind::Query";
      }
      {
        label = "running session requirement";
        needle = "ControlSessionState::Running";
      }
      {
        label = "quantum delta helper";
        needle = "acknowledgement_delta_quanta";
      }
      {
        label = "bounded quantum validation";
        needle = "delta > bound_quanta";
      }
      {
        label = "not wall-clock documented";
        needle = "Wall-clock";
      }
      {
        label = "live session probe";
        needle = "pub struct ControlResponsiveSessionProbe";
      }
      {
        label = "running-session issue route";
        needle = "issue_against_running_session";
      }
      {
        label = "snapshot command mapping";
        needle = "ControlOperationKind::Snapshot => SessionCommand::Snapshot";
      }
      {
        label = "fork command mapping";
        needle = "ControlOperationKind::Fork => SessionCommand::fork_current()";
      }
      {
        label = "inject command mapping";
        needle = "ControlOperationKind::Inject => SessionCommand::Inject";
      }
      {
        label = "query command mapping";
        needle = "ControlOperationKind::Query => SessionCommand::query_snapshot()";
      }
      {
        label = "pause command mapping";
        needle = "ControlOperationKind::Pause => SessionCommand::Pause";
      }
      {
        label = "rejected required operation error";
        needle = "RequiredOperationRejected";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-api/src/control_responsive.rs" apiControl [
      {
        label = "wall-clock duration type";
        needle = "Duration";
      }
      {
        label = "wall-clock instant type";
        needle = "Instant";
      }
      {
        label = "system wall-clock type";
        needle = "SystemTime";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_responsive.rs" apiGateTest [
      {
        label = "implemented API gate success test";
        needle = "gate_control_responsive_accepts_required_ops_within_quantum_bound";
      }
      {
        label = "API gate unbounded rejection test";
        needle = "gate_control_responsive_rejects_wall_clock_shaped_or_unbounded_evidence";
      }
      {
        label = "API gate running session and coverage test";
        needle = "gate_control_responsive_requires_running_session_and_all_operation_classes";
      }
      {
        label = "API success test uses live probe fixture";
        needle = "ControlResponsiveSessionProbe::new(sender.clone(), live)";
      }
      {
        label = "API success test issues through probe";
        needle = ".probe\n                .issue_against_running_session(operation)";
      }
      {
        label = "API fixture records delivered scheduler control";
        needle = "observed_control_operations";
      }
      {
        label = "API asserts delivered scheduler control";
        needle = "SchedulerControlOperationKind::Snapshot";
      }
      {
        label = "required rejection fails";
        needle = "RequiredOperationRejected";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-api/tests/gate_control_responsive.rs" apiGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/Cargo.toml" daemonManifest [
      {
        label = "daemon uses API contract";
        needle = "crucible-api = { path = \"../crucible-api\" }";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/lib.rs" daemonLib [
      {
        label = "daemon control-responsive module";
        needle = "pub mod control_responsiveness;";
      }
      {
        label = "daemon validation export";
        needle = "validate_daemon_control_responsiveness";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/src/control_responsiveness.rs" daemonControl [
      {
        label = "daemon API validation call";
        needle = "validate_control_responsiveness";
      }
      {
        label = "daemon quantum bound";
        needle = "DAEMON_CONTROL_RESPONSIVE_QUANTUM_BOUND";
      }
      {
        label = "daemon live route";
        needle = "pub struct DaemonControlResponsiveRoute";
      }
      {
        label = "daemon route issues through API probe";
        needle = "self.probe.issue_against_running_session(operation).await";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/tests/gate_control_responsive.rs" daemonGateTest [
      {
        label = "implemented daemon gate test";
        needle = "gate_control_responsive_daemon_routes_use_api_quantum_bound";
      }
      {
        label = "daemon test uses live API route";
        needle = "DaemonControlResponsiveRoute::new(fixture.probe.clone())";
      }
      {
        label = "daemon fixture records delivered scheduler control";
        needle = "observed_control_operations";
      }
      {
        label = "daemon tests rejected required operation";
        needle = "RequiredOperationRejected";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-daemon/tests/gate_control_responsive.rs" daemonGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionGateTest [
      {
        label = "session live snapshot read";
        needle = "live.read()";
      }
      {
        label = "session snapshot command";
        needle = "SessionCommand::Snapshot";
      }
      {
        label = "session fork command";
        needle = "SessionCommand::fork_current()";
      }
      {
        label = "session inject command";
        needle = "SessionCommand::Inject";
      }
      {
        label = "session query command";
        needle = "SessionCommand::query_snapshot()";
      }
      {
        label = "session pause command";
        needle = "SessionCommand::Pause";
      }
      {
        label = "session acknowledgement counter";
        needle = "control_acknowledgements";
      }
      {
        label = "session quantum measurement";
        needle = "quanta_after_request <= 1";
      }
      {
        label = "session quantum loop consumes control operations";
        needle = "let control = request.control;";
      }
      {
        label = "session asserts delivered scheduler control";
        needle = "observed_control_operations(&observed_control)";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" harnessLib [
      {
        label = "catalog control-responsive implemented";
        needle = "name: \"gate:control-responsive\",\n        phase: GatePhase::Phase5,\n        owner: \"crucible-session\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "API control-responsive target implemented";
        needle = "package: \"crucible-api\",\n        test_target: \"gate_control_responsive\",\n        required_features: &[],\n        placeholder: false,";
      }
      {
        label = "daemon control-responsive target implemented";
        needle = "package: \"crucible-daemon\",\n        test_target: \"gate_control_responsive\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetNix [
      {
        label = "API control-responsive Nix target implemented";
        needle = "package = \"crucible-api\";\n      testTarget = \"gate_control_responsive\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
      {
        label = "daemon control-responsive Nix target implemented";
        needle = "package = \"crucible-daemon\";\n      testTarget = \"gate_control_responsive\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
      {
        label = "placeholder count updated";
        needle = "placeholder_targets=2";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 green control-responsive gate";
        needle = "controlResponsive = import ./phase5-control-responsive.nix";
      }
      {
        label = "phase5 control-responsive attr path";
        needle = "attrPath = \"checks.crucible.phase5.gates.controlResponsive\"";
      }
    ]
    ++ forbiddenFailuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 red control-responsive placeholder";
        needle = "controlResponsive = redGate {\n        attrPath = \"checks.crucible.phase5.gates.controlResponsive\"";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-protocol-setup-failure.nix" protocolSetupFailure [
      {
        label = "protocol setup-failure depends on control-responsive gate";
        needle = "controlResponsiveGate = import ./phase5-control-responsive.nix";
      }
      {
        label = "protocol setup-failure builds control-responsive gate";
        needle = "controlResponsiveGate\n        pkgs.coreutils";
      }
      {
        label = "protocol setup-failure checks control-responsive result";
        needle = "grep -q 'gate=gate:control-responsive' \"\${controlResponsiveGate}/result\"";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-protocol-shutdown-escalation.nix" protocolShutdownEscalation [
      {
        label = "protocol shutdown-escalation depends on control-responsive gate";
        needle = "controlResponsiveGate = import ./phase5-control-responsive.nix";
      }
      {
        label = "protocol shutdown-escalation builds control-responsive gate";
        needle = "controlResponsiveGate\n        pkgs.coreutils";
      }
      {
        label = "protocol shutdown-escalation checks control-responsive result";
        needle = "grep -q 'gate=gate:control-responsive' \"\${controlResponsiveGate}/result\"";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 control-responsive check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-control-responsive";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ] ++ dependencies;

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
          name = "run-control-responsive";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-control-responsive-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-session \
              --test gate_control_responsive \
              -- --test-threads=1

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-control-responsive-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-api \
              --test gate_control_responsive \
              -- --test-threads=1

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-control-responsive-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-daemon \
              --test gate_control_responsive \
              -- --test-threads=1

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            gate=gate:control-responsive
            backend=crucible-sim-double-adapter
            real_qemu_required=false
            measured_in=quanta
            quantum_bound=1
            session_required_ops_ack_lte_one_quantum=true
            scheduler_payload_ops=snapshot,inject,query
            pause_ack=actor-boundary-state-transition
            api_required_ops=pause,snapshot,inject,query
            daemon_uses_api_contract=true
            RESULT
          '';
        }
      ];
    }
