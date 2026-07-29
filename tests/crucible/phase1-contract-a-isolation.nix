{
  pkgs,
  lib,
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };
  simLib = builtins.readFile ../../crates/crucible-sim/src/lib.rs;
  contractA = builtins.readFile ../../crates/crucible-sim/src/contract_a.rs;
  contractATests = builtins.readFile ../../crates/crucible-sim/tests/contract_a.rs;
  simCargo = builtins.readFile ../../crates/crucible-sim/Cargo.toml;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "crates/crucible-sim/src/lib.rs" simLib [
      {
        label = "contract_a module export";
        needle = "pub mod contract_a;";
      }
      {
        label = "crate map references Contract A";
        needle = "[`contract_a`] owns the isolated single-VM Contract A driver";
      }
    ]
    ++ failuresFor "crates/crucible-sim/src/contract_a.rs" contractA [
      {
        label = "Contract A config";
        needle = "pub struct ContractAConfig";
      }
      {
        label = "recorded icount input";
        needle = "pub struct RecordedInput";
      }
      {
        label = "vCPU register-file sample request";
        needle = "pub struct VcpuRegisterFileRequest";
      }
      {
        label = "single-VM driver";
        needle = "pub struct ContractADriver";
      }
      {
        label = "VM execution boundary";
        needle = "pub trait ContractAVm";
      }
      {
        label = "recorded input injection boundary";
        needle = "fn inject_recorded_input(";
      }
      {
        label = "vCPU register-file sampling boundary";
        needle = "fn sample_vcpu_register_file(";
      }
      {
        label = "aggregate retire request";
        needle = "pub struct RetireRequest";
      }
      {
        label = "in-process VM double";
        needle = "pub struct HashingContractAVm";
      }
      {
        label = "isolated run entrypoint";
        needle = "pub fn run<Vm: ContractAVm>";
      }
      {
        label = "recorded input monotonic validation";
        needle = "RecordedInputOrder";
      }
      {
        label = "recorded input interval validation";
        needle = "RecordedInputOutsideRun";
      }
      {
        label = "RR vCPU cursor";
        needle = "fn vcpu_for_icount";
      }
      {
        label = "multi-vCPU fingerprint sample";
        needle = "pub struct ContractAMultiVcpuFingerprintSample";
      }
      {
        label = "per-vCPU register-file fingerprint entry";
        needle = "pub struct ContractAVcpuRegisterFileSample";
      }
      {
        label = "RR cursor fingerprint entry";
        needle = "pub struct ContractARoundRobinCursorSample";
      }
      {
        label = "run carries multi-vCPU fingerprint trajectory";
        needle = "pub multi_vcpu_fingerprint_trajectory: Vec<ContractAMultiVcpuFingerprintSample>";
      }
      {
        label = "aggregate-icount RR cursor helper";
        needle = "fn rr_cursor_for_aggregate_icount";
      }
      {
        label = "multi-vCPU fingerprint helper";
        needle = "fn multi_vcpu_fingerprint_sample";
      }
      {
        label = "vCPU register sample error";
        needle = "VmVcpuRegisterSample";
      }
      {
        label = "run fingerprint";
        needle = "fn run_fingerprint";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/contract_a.rs" contractATests [
      {
        label = "identical replay test marker";
        needle = "contract_a_driver_replays_recorded_inputs_identically";
      }
      {
        label = "VM boundary feeding test marker";
        needle = "contract_a_driver_feeds_recorded_inputs_into_vm_boundary";
      }
      {
        label = "input/config sensitivity test marker";
        needle = "contract_a_driver_is_sensitive_to_seed_cmdline_and_input_payload";
      }
      {
        label = "future input prefix-causality test marker";
        needle = "contract_a_driver_preserves_prefix_before_future_inputs";
      }
      {
        label = "horizon extension prefix test marker";
        needle = "contract_a_driver_preserves_prefix_when_run_horizon_extends";
      }
      {
        label = "RR cursor isolation test marker";
        needle = "contract_a_driver_models_fixed_rr_vcpu_cursor_without_live_peers";
      }
      {
        label = "all-vCPU fingerprint test marker";
        needle = "contract_a_multi_vcpu_fingerprint_includes_every_vcpu_and_rr_cursor";
      }
      {
        label = "bit-identical multi-vCPU trajectory test marker";
        needle = "contract_a_multi_vcpu_fingerprint_trajectory_is_bit_identical_across_runs";
      }
      {
        label = "register-file sensitivity test marker";
        needle = "contract_a_multi_vcpu_fingerprint_changes_when_register_file_changes";
      }
      {
        label = "non-monotonic input rejection test marker";
        needle = "contract_a_driver_rejects_non_monotonic_recorded_inputs";
      }
      {
        label = "out-of-interval input rejection test marker";
        needle = "contract_a_driver_rejects_out_of_interval_recorded_inputs";
      }
    ]
    ++ forbiddenFor "crates/crucible-sim/Cargo.toml" simCargo [
      {
        label = "scheduler crate dependency";
        needle = "crucible =";
      }
      {
        label = "transport crate dependency";
        needle = "crucible-shmem";
      }
      {
        label = "async runtime dependency";
        needle = "tokio";
      }
      {
        label = "wall-clock dependency";
        needle = "time";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-7 checklist complete";
        needle = "- [x] **T-DET-7**";
      }
      {
        label = "T-DET-28 checklist complete";
        needle = "- [x] **T-DET-28**";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes Contract A isolation check";
        needle = "contractAIsolation = import ./phase1-contract-a-isolation.nix";
      }
      {
        label = "layer0 gate lists T-DET-7";
        needle = "\"T-DET-7\"";
      }
      {
        label = "layer0 gate lists T-DET-28";
        needle = "\"T-DET-28\"";
      }
      {
        label = "layer0 gate depends on Contract A isolation";
        needle = "phase1-contract-a-isolation.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 Contract A isolation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-contract-a-isolation";
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
          name = "run-contract-a-isolation";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-contract-a-isolation-target" \
              -p crucible-sim \
              --test contract_a \
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
            check=checks.crucible.phase1.contractAIsolation
            gate=gate:layer0-determinism
            tasks=T-DET-7,T-DET-28
            driver=crucible-sim::contract_a::ContractADriver
            inputs=icount-stamped-recorded-list
            live_scheduler_transport=false
            rr_vcpu_cursor=fixed-content-addressed
            multi_vcpu_driver=N>1-single-node-rr-icount-model
            multi_vcpu_fingerprint=per-vcpu-register-files-plus-rr-cursor
            aggregate_icount_trajectory=bit-identical-across-runs
            fingerprint_key=node-aggregate-icount
            recorded_inputs_enforced=monotonic-within-run
            rust_test=crucible-sim::contract_a
            status=contract-a-isolated-single-vm-and-multi-vcpu-model
            RESULT
          '';
        }
      ];
    }
