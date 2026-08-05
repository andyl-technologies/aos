{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolShutdownEscalation",
  taskIds ? ["T-PROTO-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  qemuCargo = builtins.readFile ../../crates/crucible-qemu/Cargo.toml;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  shutdownLib = builtins.readFile ../../crates/crucible-qemu/src/shutdown.rs;
  shutdownTest = builtins.readFile ../../crates/crucible-qemu/tests/shutdown.rs;
  protocolSpec = builtins.readFile ../../docs/rfcs/0010-crucible/14-protocol.md;
  defaultChecks = builtins.readFile ./default.nix;
  controlResponsiveGate = import ./phase5-control-responsive.nix {
    inherit pkgs lib;
    attrPath = "checks.crucible.phase5.gates.controlResponsive";
    taskIds = ["T-HARN-15"];
  };

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-qemu/Cargo.toml" qemuCargo [
      {
        label = "Unix signal dependency";
        needle = "libc = { workspace = true }";
      }
      {
        label = "protocol Quit dependency";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "shutdown module";
        needle = "mod shutdown;";
      }
      {
        label = "shutdown exports";
        needle = "shutdown_qemu_child";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/shutdown.rs" shutdownLib [
      {
        label = "shutdown rung enum";
        needle = "pub enum QemuShutdownRung";
      }
      {
        label = "canonical rung order";
        needle = "pub const QEMU_SHUTDOWN_ESCALATION_ORDER";
      }
      {
        label = "control Quit rung";
        needle = "QemuShutdownRung::ControlQuit";
      }
      {
        label = "QMP quit rung";
        needle = "QemuShutdownRung::QmpQuit";
      }
      {
        label = "SIGTERM rung";
        needle = "QemuShutdownRung::Sigterm";
      }
      {
        label = "SIGKILL rung";
        needle = "QemuShutdownRung::Sigkill";
      }
      {
        label = "reap rung";
        needle = "QemuShutdownRung::Reap";
      }
      {
        label = "bounded shutdown policy";
        needle = "pub struct QemuShutdownPolicy";
      }
      {
        label = "shutdown target trait";
        needle = "pub trait QemuShutdownTarget";
      }
      {
        label = "runner function";
        needle = "pub fn shutdown_qemu_child";
      }
      {
        label = "target control Quit hook";
        needle = "fn send_control_quit";
      }
      {
        label = "target QMP quit hook";
        needle = "fn send_qmp_quit";
      }
      {
        label = "target SIGTERM hook";
        needle = "fn send_sigterm";
      }
      {
        label = "target SIGKILL hook";
        needle = "fn send_sigkill";
      }
      {
        label = "target reap hook";
        needle = "fn reap";
      }
      {
        label = "nonfatal failure report";
        needle = "pub struct QemuShutdownFailure";
      }
      {
        label = "failure recording continues escalation";
        needle = "report.failures.push(QemuShutdownFailure { rung, source });\n            continue;";
      }
      {
        label = "leak error";
        needle = "LeakedChild";
      }
      {
        label = "concrete protocol Quit writer";
        needle = "pub fn send_control_quit_frame";
      }
      {
        label = "Quit helper uses protocol encoder";
        needle = "control_encode_host_msg(&HostMsg::Quit)";
      }
      {
        label = "Quit helper uses protocol frame writer";
        needle = "write_control_frame(writer, &frame)";
      }
      {
        label = "QMP quit command constant";
        needle = "pub const QMP_QUIT_COMMAND";
      }
      {
        label = "concrete QMP quit writer";
        needle = "pub fn send_qmp_quit_command";
      }
      {
        label = "Unix child adapter";
        needle = "pub struct UnixQemuChildShutdownTarget";
      }
      {
        label = "Unix adapter writes concrete Quit";
        needle = "send_control_quit_frame(&mut self.control)";
      }
      {
        label = "Unix adapter writes concrete QMP quit";
        needle = "send_qmp_quit_command(&mut self.qmp)";
      }
      {
        label = "Unix SIGTERM delivery";
        needle = "signal_child(self.child.id(), libc::SIGTERM";
      }
      {
        label = "Unix SIGKILL delivery";
        needle = "signal_child(self.child.id(), libc::SIGKILL";
      }
      {
        label = "no host Instant use";
        needle = "let mut waited = Duration::ZERO;";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/shutdown.rs" shutdownTest [
      {
        label = "unresponsive child escalates to SIGKILL";
        needle = "shutdown_escalates_to_sigkill_and_reaps_unresponsive_child";
      }
      {
        label = "QMP exit stops escalation";
        needle = "shutdown_stops_escalating_after_qmp_exit";
      }
      {
        label = "leak reporting test";
        needle = "shutdown_reports_leak_when_reap_cannot_collect_child";
      }
      {
        label = "target failure test";
        needle = "shutdown_records_polite_failures_and_continues_to_reap";
      }
      {
        label = "canonical Quit/QMP byte test";
        needle = "control_quit_and_qmp_helpers_write_canonical_shutdown_bytes";
      }
      {
        label = "real Unix adapter process test";
        needle = "unix_adapter_continues_after_broken_polite_channels_and_reaps_child";
      }
      {
        label = "real QEMU adapter process test";
        needle = "unix_adapter_reaps_real_qemu_child_when_polite_channels_fail";
      }
      {
        label = "real QEMU env";
        needle = "CRUCIBLE_QEMU_SHUTDOWN_TEST_BINARY";
      }
      {
        label = "real child process";
        needle = "Command::new(\"sleep\")";
      }
      {
        label = "real adapter under polite failures";
        needle = "UnixQemuChildShutdownTarget::new(child, FailingWriter, FailingWriter)";
      }
      {
        label = "protocol order test";
        needle = "shutdown_order_matches_protocol_spec";
      }
      {
        label = "mock unresponsive path";
        needle = "QemuChildWait::StillRunning";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol shutdown-escalation check";
        needle = "protocolShutdownEscalation = import ./phase2-protocol-shutdown-escalation.nix";
      }
      {
        label = "canonical control-responsive gate is green";
        needle = "controlResponsive = import ./phase5-control-responsive.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol shutdown-escalation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-shutdown-escalation";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        controlResponsiveGate
        pkgs.coreutils
        pkgs.grep
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-protocol-shutdown-escalation";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            grep -q 'gate=gate:control-responsive' "${controlResponsiveGate}/result"
            CRUCIBLE_QEMU_SHUTDOWN_TEST_BINARY="${pkgs.qemu-crucible}/bin/qemu-system-x86_64" \
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-shutdown-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test shutdown \
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
            gate=gate:control-responsive
            rust_test=crucible-qemu::shutdown
            real_qemu_proof=crucible-qemu::shutdown::unix_adapter_reaps_real_qemu_child_when_polite_channels_fail
            order=Quit,QMP-quit,SIGTERM,SIGKILL,reap
            no_leak=real-qemu-child-reaped
            RESULT
          '';
        }
      ];
    }
