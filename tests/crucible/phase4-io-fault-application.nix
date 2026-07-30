{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.ioFaultApplication",
  taskIds ? ["T-FAULT-9"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  deviceBridge = builtins.readFile ../../crates/crucible/src/device.rs;
  deviceSubnode = builtins.readFile ../../crates/crucible/src/device_subnode.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  faultModel = import ./_crucible-model-source.nix {inherit lib;};
  ioFaults = builtins.readFile ../../crates/crucible-device/src/fault.rs;
  faultTest = builtins.readFile ../../crates/crucible/tests/io_fault_application.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-9 completion note";
        needle = "Completed by `checks.crucible.phase4.ioFaultApplication`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" faultModel [
      {
        label = "block duplicate fault";
        needle = "BlockFault::Duplicate";
      }
      {
        label = "block corruption fault";
        needle = "BlockFault::Corruption";
      }
      {
        label = "block bandwidth fault";
        needle = "BlockFault::Bandwidth";
      }
      {
        label = "9p reorder fault";
        needle = "NinePFault::Reorder";
      }
      {
        label = "9p duplicate fault";
        needle = "NinePFault::Duplicate";
      }
      {
        label = "9p corruption fault";
        needle = "NinePFault::Corruption";
      }
      {
        label = "9p bandwidth fault";
        needle = "NinePFault::Bandwidth";
      }
      {
        label = "I/O corruption combination";
        needle = "pub struct CombinedIoCorruptionFault";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/fault.rs" ioFaults [
      {
        label = "bit-rate bandwidth caps";
        needle = "pub bandwidth_bits_per_sec: Vec<u64>";
      }
      {
        label = "overlapping failure rates";
        needle = "pub additional_loss: Vec<Probability>";
      }
      {
        label = "drop-mode flag";
        needle = "pub drop_on_loss: bool";
      }
      {
        label = "9p errno payload";
        needle = "pub failure_errno: Option<u32>";
      }
      {
        label = "additional errno payloads";
        needle = "pub additional_failure_errno: Vec<u32>";
      }
      {
        label = "exact bit-rate delay";
        needle = "pub fn serialization_delay_bits_per_sec";
      }
      {
        label = "drop outcome";
        needle = "pub dropped: bool";
      }
      {
        label = "selected failure errno";
        needle = "pub failure_errno: Option<u32>";
      }
    ]
    ++ failuresFor "crates/crucible/src/device.rs" deviceBridge [
      {
        label = "block lowering";
        needle = "pub fn block_faults_from_combined_block";
      }
      {
        label = "9p lowering";
        needle = "pub fn ninep_faults_from_combined_ninep";
      }
      {
        label = "block live sub-node application";
        needle = "pub fn apply_combined_block_faults_to_subnode";
      }
      {
        label = "block live application plus materialization";
        needle = "pub fn apply_combined_block_faults_to_subnode_and_state";
      }
      {
        label = "9p live sub-node application";
        needle = "pub fn apply_combined_ninep_faults_to_subnode";
      }
      {
        label = "9p live application plus materialization";
        needle = "pub fn apply_combined_ninep_faults_to_subnode_and_state";
      }
      {
        label = "block drop lowering";
        needle = "table.drop_on_loss = matches!(faults.failure_mode, Some(IoFailureMode::Drop))";
      }
      {
        label = "9p errno lowering";
        needle = "table.failure_errno = Some(failure.errno.code() as u32)";
      }
      {
        label = "materialized bit-rate bandwidth active fault";
        needle = "!faults.bandwidth_bits_per_sec.is_empty()";
      }
      {
        label = "materialized overlapping failure active fault";
        needle = ".additional_loss";
      }
    ]
    ++ failuresFor "crates/crucible/src/device_subnode.rs" deviceSubnode [
      {
        label = "delivery wrapper";
        needle = "pub struct DeviceDelivery";
      }
      {
        label = "decision-only drop delivery";
        needle = "pub completion: Option<IoCompletion>";
      }
      {
        label = "explicit delivery source-node tie-break";
        needle = "pub source_node: u32";
      }
      {
        label = "explicit delivery sequence tie-break";
        needle = "pub sequence: u32";
      }
      {
        label = "live fault table accessor";
        needle = "pub fn io_faults(&self) -> &IoFaults";
      }
      {
        label = "live fault table installer";
        needle = "pub fn set_io_faults(&mut self, faults: IoFaults)";
      }
      {
        label = "drop suppresses payload";
        needle = "if outcome.dropped";
      }
      {
        label = "block native error encoding";
        needle = "BlockResponse::error(response.request_id)";
      }
      {
        label = "9p native error encoding";
        needle = "ninep_codec::encode_rlerror(tag, errno)";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "block lowering export";
        needle = "block_faults_from_combined_block";
      }
      {
        label = "block apply plus state export";
        needle = "apply_combined_block_faults_to_subnode_and_state";
      }
      {
        label = "9p lowering export";
        needle = "ninep_faults_from_combined_ninep";
      }
      {
        label = "9p apply plus state export";
        needle = "apply_combined_ninep_faults_to_subnode_and_state";
      }
      {
        label = "sub-node delivery export";
        needle = "DeviceDelivery";
      }
      {
        label = "I/O corruption combination export";
        needle = "CombinedIoCorruptionFault";
      }
    ]
    ++ failuresFor "crates/crucible/tests/io_fault_application.rs" faultTest [
      {
        label = "block resolve-path test";
        needle = "combined_block_faults_apply_to_subnode_resolve_path";
      }
      {
        label = "block error/drop test";
        needle = "block_failures_encode_error_status_or_drop_without_completion";
      }
      {
        label = "partial-delivery activation freeze test";
        needle = "live_fault_activation_does_not_rewrite_already_resolved_block_work";
      }
      {
        label = "9p resolve-path test";
        needle = "combined_9p_faults_apply_to_subnode_resolve_path";
      }
      {
        label = "9p errno test";
        needle = "ninep_failure_encodes_rlerror_with_selected_errno";
      }
      {
        label = "active-fault materialization test";
        needle = "active_block_and_9p_faults_enter_materialized_scheduler_state";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 gate wiring";
        needle = "ioFaultApplication = import ./phase4-io-fault-application.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 io-fault-application check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-io-fault-application";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
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
          name = "run-io-fault-application";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-io-fault-application-target" \
              -p crucible \
              --test io_fault_application \
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
            block=latency-jitter-reorder-failure-duplicate-corrupt-bandwidth
            ninep=latency-jitter-reorder-failure-duplicate-corrupt-bandwidth
            drops=decision-only-resolve-items
            materialized_state=active-io-faults
            RESULT
          '';
        }
      ];
    }
