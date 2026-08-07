{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.protocolSetupFailure",
  taskIds ? ["T-PROTO-8"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  qemuCargo = builtins.readFile ../../crates/crucible-qemu/Cargo.toml;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  setupFailureLib = builtins.readFile ../../crates/crucible-qemu/src/setup_failure.rs;
  setupFailureTest = builtins.readFile ../../crates/crucible-qemu/tests/setup_failure.rs;
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
        label = "qemu depends on real shmem validator";
        needle = "crucible-shmem = { path = \"../crucible-shmem\" }";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "setup failure module";
        needle = "mod setup_failure;";
      }
      {
        label = "forced setup driver export";
        needle = "complete_qemu_node_setup";
      }
      {
        label = "setup failure exports";
        needle = "abort_qemu_setup_failure";
      }
      {
        label = "setup failure source exports";
        needle = "QemuSetupFailureSource";
      }
      {
        label = "region validation exports";
        needle = "validate_qemu_setup_region_header";
      }
      {
        label = "setup driver trait export";
        needle = "QemuSetupDriver";
      }
      {
        label = "node setup outcome export";
        needle = "QemuNodeSetup";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/setup_failure.rs" setupFailureLib [
      {
        label = "setup failure classifier";
        needle = "pub enum QemuSetupFailureKind";
      }
      {
        label = "no version overlap variant";
        needle = "NoProtocolVersionOverlap";
      }
      {
        label = "ABI mismatch variant";
        needle = "AbiMismatch";
      }
      {
        label = "bad slot variant";
        needle = "BadSlot";
      }
      {
        label = "wrong fd count variant";
        needle = "WrongFdCount";
      }
      {
        label = "short invalid region variant";
        needle = "ShortOrInvalidRegion";
      }
      {
        label = "nonzero setup ack variant";
        needle = "NonZeroSetupAck";
      }
      {
        label = "premature socket close variant";
        needle = "PrematureSocketClose";
      }
      {
        label = "unexpected setup failure variant";
        needle = "UnexpectedSetupProtocolFailure";
      }
      {
        label = "setup source enum";
        needle = "pub enum QemuSetupFailureSource";
      }
      {
        label = "setup driver trait";
        needle = "pub trait QemuSetupDriver";
      }
      {
        label = "driver handshake step";
        needle = "fn accept_handshake";
      }
      {
        label = "driver descriptor step";
        needle = "fn receive_setup_descriptors";
      }
      {
        label = "driver region step";
        needle = "fn validate_setup_region";
      }
      {
        label = "driver setup ack step";
        needle = "fn accept_setup_ack";
      }
      {
        label = "source reason classifier";
        needle = "pub fn reason(&self) -> QemuSetupFailureKind";
      }
      {
        label = "handshake classifier";
        needle = "pub const fn from_handshake_error";
      }
      {
        label = "descriptor classifier";
        needle = "pub const fn from_descriptor_handover_error";
      }
      {
        label = "setup ack classifier";
        needle = "pub const fn from_setup_completion_error";
      }
      {
        label = "region validation classifier";
        needle = "pub const fn from_region_validation_error";
      }
      {
        label = "real shmem region validation error";
        needle = "RegionSetupValidationError";
      }
      {
        label = "real shmem validated region token";
        needle = "ValidatedSetupRegion";
      }
      {
        label = "real region header validator wrapper";
        needle = "pub fn validate_qemu_setup_region_header";
      }
      {
        label = "real shmem validator invoked";
        needle = "validate_setup_region_header(snapshot, region_len)";
      }
      {
        label = "schedulable qemu setup token";
        needle = "pub struct QemuSchedulableNodeSetup";
      }
      {
        label = "node setup outcome";
        needle = "pub enum QemuNodeSetup";
      }
      {
        label = "schedulable outcome";
        needle = "Schedulable(QemuSchedulableNodeSetup)";
      }
      {
        label = "failed outcome";
        needle = "Failed(FailedQemuNodeSetup)";
      }
      {
        label = "failed node setup token";
        needle = "pub struct FailedQemuNodeSetup";
      }
      {
        label = "failed node cannot schedule";
        needle = "pub const fn can_schedule(&self) -> bool {\n        false\n    }";
      }
      {
        label = "setup abort error";
        needle = "pub enum QemuSetupAbortError";
      }
      {
        label = "source-driven abort runner";
        needle = "pub fn abort_qemu_setup_failure";
      }
      {
        label = "forced setup runner";
        needle = "pub fn complete_qemu_node_setup";
      }
      {
        label = "handshake failure aborts";
        needle = "target.accept_handshake()";
      }
      {
        label = "descriptor failure aborts";
        needle = "target.receive_setup_descriptors()";
      }
      {
        label = "region failure aborts";
        needle = "target.validate_setup_region()";
      }
      {
        label = "setup ack failure aborts";
        needle = "target.accept_setup_ack()";
      }
      {
        label = "failure path returns failed outcome";
        needle = "map(QemuNodeSetup::Failed)";
      }
      {
        label = "shutdown escalation invoked";
        needle = "shutdown_qemu_child(target, policy)";
      }
      {
        label = "shutdown reason preserved";
        needle = "reason: reason.clone()";
      }
      {
        label = "premature close recognizes truncated prefix";
        needle = "FrameIoError::TruncatedLengthPrefix";
      }
      {
        label = "premature close recognizes truncated payload";
        needle = "FrameIoError::TruncatedPayload";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/tests/setup_failure.rs" setupFailureTest [
      {
        label = "setup driver all variants abort test";
        needle = "setup_driver_failures_abort_escalate_reap_and_never_schedule";
      }
      {
        label = "setup driver success token test";
        needle = "setup_driver_returns_schedulable_token_only_after_all_setup_steps";
      }
      {
        label = "source-driven test inputs";
        needle = "proto21_failure_sources";
      }
      {
        label = "handshake classifier test";
        needle = "setup_failure_classifies_proto21_handshake_errors";
      }
      {
        label = "descriptor and ack classifier test";
        needle = "setup_failure_classifies_descriptor_setup_ack_and_real_region_failures";
      }
      {
        label = "leak error reason test";
        needle = "setup_abort_error_preserves_failure_reason_when_child_leaks";
      }
      {
        label = "real child reap proof";
        needle = "setup_driver_reaps_real_child_and_never_schedules";
      }
      {
        label = "real QEMU reap proof";
        needle = "setup_driver_reaps_real_qemu_child_for_invalid_region_when_env_set";
      }
      {
        label = "real QEMU env var";
        needle = "CRUCIBLE_QEMU_SETUP_FAILURE_TEST_BINARY";
      }
      {
        label = "Unix shutdown adapter exercised";
        needle = "UnixQemuChildShutdownTarget";
      }
      {
        label = "no schedule assertion";
        needle = "assert!(!failed.can_schedule());";
      }
      {
        label = "setup driver called";
        needle = "complete_qemu_node_setup";
      }
      {
        label = "schedulable token can schedule only on success";
        needle = "QemuNodeSetup::Schedulable";
      }
      {
        label = "full shutdown order assertion";
        needle = "QemuShutdownRung::Sigkill";
      }
      {
        label = "wrong fd count exercised";
        needle = "DescriptorHandoverError::WrongDescriptorCount";
      }
      {
        label = "nonzero setup ack exercised";
        needle = "SetupCompletionError::NonZeroSetupAck";
      }
      {
        label = "short invalid region exercised";
        needle = "validate_qemu_setup_region_header";
      }
      {
        label = "short region comes from real validation";
        needle = "short_region_error";
      }
      {
        label = "invalid ABI marker comes from real header";
        needle = "invalid_abi_marker_error";
      }
      {
        label = "real shmem header constructed";
        needle = "RegionHeader::new";
      }
      {
        label = "real child command";
        needle = "Command::new(\"sleep\")";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/14-protocol.md" protocolSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes protocol setup-failure check";
        needle = "protocolSetupFailure = import ./phase2-protocol-setup-failure.nix";
      }
      {
        label = "control-responsive gate is green";
        needle = "controlResponsive = import ./phase5-control-responsive.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 protocol setup-failure check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-protocol-setup-failure";
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
          name = "run-protocol-setup-failure";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            grep -q 'gate=gate:control-responsive' "${controlResponsiveGate}/result"
            if grep -q 'pub fn abort_failed_qemu_setup' crates/crucible-qemu/src/setup_failure.rs; then
              echo "setup failure gate requires source-driven abort API, not public kind-only abort"
              exit 1
            fi
            CRUCIBLE_QEMU_SETUP_FAILURE_TEST_BINARY="${pkgs.qemu-crucible}/bin/qemu-system-x86_64" \
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-protocol-setup-failure-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --test setup_failure \
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
            gate=gate:abi-conformance,gate:control-responsive
            rust_test=crucible-qemu::setup_failure
            failure_modes=no-version-overlap,abi-mismatch,bad-slot,wrong-fd-count,short-invalid-region,nonzero-setup-ack,premature-socket-close
            abort=unschedulable-node,shutdown-escalation,real-qemu-child-reaped
            setup_driver=complete_qemu_node_setup
            setup_region_proof=validate_qemu_setup_region_header
            RESULT
          '';
        }
      ];
    }
