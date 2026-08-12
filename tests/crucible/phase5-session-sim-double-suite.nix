{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.sessionSimDoubleSuite",
  taskIds ? ["T-SESS-12" "T-PAT-6"],
  openTaskIds ? [],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  sessionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/20-session-control-plane.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  harnessDoc = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  patternsDoc = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
  defaultChecks = builtins.readFile ./default.nix;
  sessionManifest = builtins.readFile ../../crates/crucible-session/Cargo.toml;
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  sessionGateTest = builtins.readFile ../../crates/crucible-session/tests/gate_control_responsive.rs;
  sessionExplorationForkTest = builtins.readFile ../../crates/crucible-session/tests/gate_exploration_fork.rs;
  sessionExplorationLifecycleTest = builtins.readFile ../../crates/crucible-session/tests/gate_exploration_lifecycle.rs;
  apiManifest = builtins.readFile ../../crates/crucible-api/Cargo.toml;
  apiGateTest = builtins.readFile ../../crates/crucible-api/tests/gate_control_responsive.rs;
  daemonManifest = builtins.readFile ../../crates/crucible-daemon/Cargo.toml;
  daemonGateTest = builtins.readFile ../../crates/crucible-daemon/tests/gate_control_responsive.rs;
  schedulerGateTest = builtins.readFile ../../crates/crucible/tests/gate_scheduler_liveness.rs;
  lifecycleCheck = builtins.readFile ./phase5-session-lifecycle.nix;
  commandCheck = builtins.readFile ./phase5-session-command-set.nix;
  controlResponsiveCheck = builtins.readFile ./phase5-control-responsive.nix;
  schedulerLivenessCheck = builtins.readFile ./phase3-scheduler-liveness.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  qemuBackendForbidden = [
    {
      label = "crucible-qemu crate import";
      needle = "crucible-qemu";
    }
    {
      label = "crucible-qemu crate import";
      needle = "crucible_qemu";
    }
    {
      label = "QemuNode backend construction";
      needle = "QemuNode";
    }
    {
      label = "external process launch";
      needle = "std::process::Command";
    }
    {
      label = "async external process launch";
      needle = "tokio::process::Command";
    }
    {
      label = "qemu binary launch";
      needle = "qemu-system";
    }
  ];

  failures =
    failuresFor "docs/rfcs/0010-crucible/20-session-control-plane.md" sessionDoc [
      {
        label = "T-SESS-12 completion note";
        needle = "Completed by `checks.crucible.phase5.sessionSimDoubleSuite`";
      }
      {
        label = "SESS-28 control-plane double rule";
        needle = "A session test that needs real QEMU to";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternsDoc [
      {
        label = "T-PAT-6 session backend completion note";
        needle = "Completed by `checks.crucible.phase5.sessionSimulationBackend` and";
      }
      {
        label = "T-PAT-6 SimDouble suite completion note";
        needle = "`checks.crucible.phase5.sessionSimDoubleSuite`";
      }
      {
        label = "T-PAT-6 SimDouble adapter claim";
        needle = "`crucible::SimDouble` quantum-loop adapter";
      }
      {
        label = "T-PAT-6 scheduler liveness harness claim";
        needle = "initialized `crucible::SimDouble` liveness harness";
      }
      {
        label = "T-PAT-6 no real QEMU claim";
        needle = "real QEMU";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 SimDouble suite completion note";
        needle = "`T-SESS-12` is completed by `checks.crucible.phase5.sessionSimDoubleSuite`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessDoc [
      {
        label = "control-plane responsiveness is double-backed";
        needle = "control-plane responsiveness       yes";
      }
      {
        label = "Contract A needs real QEMU";
        needle = "per-VM instruction determinism     NO";
      }
      {
        label = "guest non-mutation needs real QEMU";
        needle = "guest non-mutation                 NO";
      }
      {
        label = "patch inertness needs real QEMU";
        needle = "patch inertness                    NO";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "generic session engine";
        needle = "pub struct Engine<L>";
      }
      {
        label = "generic session actor";
        needle = "pub struct SessionActor<L>";
      }
      {
        label = "no raw QEMU session boundary";
        needle = "It contains no raw QEMU or shared-memory access.";
      }
    ]
    ++ forbiddenFor "crates/crucible-session/src/lib.rs" sessionLib qemuBackendForbidden
    ++ failuresFor "crates/crucible-session/Cargo.toml" sessionManifest [
      {
        label = "session test-double and test-support dev features";
        needle = "crucible = { path = \"../crucible\", features = [\"test-double\", \"test-support\"] }";
      }
      {
        label = "session protocol dev dependency";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionGateTest [
      {
        label = "session gate declares SimDouble adapter";
        needle = "const CONTROL_RESPONSIVE_BACKEND: &str = \"crucible::SimDouble quantum-loop adapter\";";
      }
      {
        label = "session gate rejects real-QEMU requirement";
        needle = "const CONTROL_RESPONSIVE_REQUIRES_REAL_QEMU: bool = false;";
      }
      {
        label = "session loop owns exported SimDouble";
        needle = "backend: SimDouble";
      }
      {
        label = "session loop constructs exported SimDouble";
        needle = "SimDouble::new(SimDoubleConfig::default())";
      }
      {
        label = "session loop drives SimulationBackend";
        needle = "SimulationBackend::step_to";
      }
      {
        label = "session loop exercises backend snapshot control";
        needle = "SimulationBackend::snapshot";
      }
      {
        label = "session loop exercises backend query control";
        needle = "SimulationBackend::fingerprint";
      }
      {
        label = "session loop exercises backend input control";
        needle = "BackendEffect::DeliverInput";
      }
      {
        label = "session gate uses in-process quantum loop";
        needle = "SimDoubleQuantumLoop::new";
      }
      {
        label = "session gate covers lifecycle start";
        needle = "SessionCommand::Start";
      }
      {
        label = "session gate covers continue";
        needle = "SessionCommand::Continue";
      }
      {
        label = "session gate covers pause";
        needle = "SessionCommand::Pause";
      }
      {
        label = "session gate covers snapshot";
        needle = "SessionCommand::query_snapshot()";
      }
      {
        label = "session gate covers query";
        needle = "SessionCommand::query_snapshot()";
      }
      {
        label = "session gate covers fork";
        needle = "SessionCommand::fork_current()";
      }
      {
        label = "session gate covers stop";
        needle = "SessionCommand::Stop";
      }
    ]
    ++ forbiddenFor "crates/crucible-session/tests/gate_control_responsive.rs" sessionGateTest qemuBackendForbidden
    ++ forbiddenFor "crates/crucible-session/tests/gate_exploration_fork.rs" sessionExplorationForkTest qemuBackendForbidden
    ++ forbiddenFor "crates/crucible-session/tests/gate_exploration_lifecycle.rs" sessionExplorationLifecycleTest qemuBackendForbidden
    ++ failuresFor "crates/crucible-api/Cargo.toml" apiManifest [
      {
        label = "API test-double and test-support dev features";
        needle = "crucible = { path = \"../crucible\", features = [\"test-double\", \"test-support\"] }";
      }
      {
        label = "API session test-support dev feature";
        needle = "crucible-session = { path = \"../crucible-session\", features = [\"test-support\"] }";
      }
      {
        label = "API protocol dev dependency";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_control_responsive.rs" apiGateTest [
      {
        label = "API gate declares SimDouble adapter";
        needle = "const CONTROL_RESPONSIVE_BACKEND: &str = \"crucible::SimDouble quantum-loop adapter\";";
      }
      {
        label = "API gate uses live SimDouble fixture";
        needle = "RunningSimDoubleControlPlane::spawn().await";
      }
      {
        label = "API loop owns exported SimDouble";
        needle = "backend: SimDouble";
      }
      {
        label = "API loop constructs exported SimDouble";
        needle = "SimDouble::new(SimDoubleConfig::default())";
      }
      {
        label = "API loop drives SimulationBackend";
        needle = "SimulationBackend::step_to";
      }
      {
        label = "API gate uses in-process quantum loop";
        needle = "SimDoubleQuantumLoop::new";
      }
    ]
    ++ forbiddenFor "crates/crucible-api/tests/gate_control_responsive.rs" apiGateTest qemuBackendForbidden
    ++ failuresFor "crates/crucible-daemon/Cargo.toml" daemonManifest [
      {
        label = "daemon test-double dev feature";
        needle = "crucible = { path = \"../crucible\", features = [\"test-double\"] }";
      }
      {
        label = "daemon protocol dev dependency";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
    ]
    ++ failuresFor "crates/crucible-daemon/tests/gate_control_responsive.rs" daemonGateTest [
      {
        label = "daemon gate declares SimDouble adapter";
        needle = "const CONTROL_RESPONSIVE_BACKEND: &str = \"crucible::SimDouble quantum-loop adapter\";";
      }
      {
        label = "daemon gate uses live SimDouble fixture";
        needle = "RunningSimDoubleControlPlane::spawn().await";
      }
      {
        label = "daemon loop owns exported SimDouble";
        needle = "backend: SimDouble";
      }
      {
        label = "daemon loop constructs exported SimDouble";
        needle = "SimDouble::new(SimDoubleConfig::default())";
      }
      {
        label = "daemon loop drives SimulationBackend";
        needle = "SimulationBackend::step_to";
      }
      {
        label = "daemon gate uses in-process quantum loop";
        needle = "SimDoubleQuantumLoop::new";
      }
    ]
    ++ forbiddenFor "crates/crucible-daemon/tests/gate_control_responsive.rs" daemonGateTest qemuBackendForbidden
    ++ failuresFor "crates/crucible/tests/gate_scheduler_liveness.rs" schedulerGateTest [
      {
        label = "scheduler liveness declares SimDouble initialized test-double path";
        needle = "const SCHEDULER_LIVENESS_BACKEND: &str = \"crucible::SimDouble liveness harness\";";
      }
      {
        label = "scheduler liveness rejects real-QEMU requirement";
        needle = "const SCHEDULER_LIVENESS_REQUIRES_REAL_QEMU: bool = false;";
      }
      {
        label = "scheduler liveness uses generated corpus";
        needle = "generated_scheduler_liveness_scenarios";
      }
      {
        label = "scheduler liveness initializes exported SimDouble";
        needle = "backend: SimDouble";
      }
      {
        label = "scheduler liveness constructs exported SimDouble";
        needle = "SimDouble::new(SimDoubleConfig::default())";
      }
      {
        label = "scheduler liveness steps SimDouble before reduction";
        needle = "SimulationBackend::step_to";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_scheduler_liveness.rs" schedulerGateTest qemuBackendForbidden
    ++ failuresFor "tests/crucible/phase5-session-lifecycle.nix" lifecycleCheck [
      {
        label = "lifecycle suite command";
        needle = "-p crucible-session";
      }
      {
        label = "lifecycle filter";
        needle = "lifecycle";
      }
    ]
    ++ failuresFor "tests/crucible/phase5-session-command-set.nix" commandCheck [
      {
        label = "command suite command";
        needle = "-p crucible-session";
      }
      {
        label = "command filter";
        needle = "rfc_command";
      }
    ]
    ++ failuresFor "tests/crucible/phase5-control-responsive.nix" controlResponsiveCheck [
      {
        label = "control-responsive session target";
        needle = "-p crucible-session";
      }
      {
        label = "control-responsive API target";
        needle = "-p crucible-api";
      }
      {
        label = "control-responsive daemon target";
        needle = "-p crucible-daemon";
      }
      {
        label = "control-responsive backend marker";
        needle = "backend=crucible-sim-double-adapter";
      }
      {
        label = "control-responsive real-QEMU false marker";
        needle = "real_qemu_required=false";
      }
    ]
    ++ failuresFor "tests/crucible/phase3-scheduler-liveness.nix" schedulerLivenessCheck [
      {
        label = "scheduler liveness target";
        needle = "--test gate_scheduler_liveness";
      }
      {
        label = "scheduler liveness test-double feature";
        needle = "--features test-double";
      }
      {
        label = "scheduler liveness test-double backend marker";
        needle = "backend=crucible-sim-double-initialized-test-double";
      }
      {
        label = "scheduler liveness real-QEMU false marker";
        needle = "real_qemu_required=false";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes SimDouble suite";
        needle = "sessionSimDoubleSuite = import ./phase5-session-sim-double-suite.nix";
      }
      {
        label = "phase5 SimDouble suite carries completed session and pattern tasks";
        needle = "taskIds = [\"T-SESS-12\" \"T-PAT-6\"]";
      }
      {
        label = "phase5 SimDouble suite attr path";
        needle = "attrPath = \"checks.crucible.phase5.sessionSimDoubleSuite\"";
      }
      {
        label = "phase5 SimDouble suite depends on session backend";
        needle = "phase5.sessionSimulationBackend";
      }
      {
        label = "phase5 SimDouble suite depends on control-responsive raw gate";
        needle = "phase5.gates.controlResponsive.rawGate";
      }
      {
        label = "phase5 SimDouble suite depends on scheduler-liveness raw gate";
        needle = "phase3.gates.schedulerLiveness.rawGate";
      }
    ];
in
  if failures != []
  then throw "crucible phase5 session SimDouble suite check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase5-session-sim-double-suite";
      version = "0";
      src = crucibleSrc;

      buildDeps =
        [
          pkgs.coreutils
          pkgs.rust
          pkgs.sed
        ]
        ++ dependencies;

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
          name = "run-session-sim-double-suite";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-sim-double-suite-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-session \
              -- --test-threads=1

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-sim-double-suite-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-api \
              --test gate_control_responsive \
              -- --test-threads=1

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-sim-double-suite-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-daemon \
              --test gate_control_responsive \
              -- --test-threads=1

            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-session-sim-double-suite-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --features test-double \
              --test gate_scheduler_liveness \
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
            component=crucible-session
            backend=crucible-sim-double-adapter
            real_qemu_required_for_control_plane=false
            real_qemu_required_for=contract-a,guest-non-mutation,patch-inertness
            suite=crucible-session:all
            gates=gate:control-responsive,gate:scheduler-liveness
            scheduler_liveness_features=test-double
            scheduler_liveness_backend=crucible-sim-double-initialized-before-pure-reduction
            RESULT
          '';
        }
      ];
    }
