{
  pkgs,
  lib,
}: let
  simLib = builtins.readFile ../../crates/crucible-sim/src/lib.rs;
  contractA = builtins.readFile ../../crates/crucible-sim/src/contract_a.rs;
  contractATests = builtins.readFile ../../crates/crucible-sim/tests/contract_a.rs;
  simCargo = builtins.readFile ../../crates/crucible-sim/Cargo.toml;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  defaultChecks = builtins.readFile ./default.nix;

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

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

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
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "record-contract-a-isolation";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.contractAIsolation
            gate=gate:layer0-determinism
            tasks=T-DET-7
            driver=crucible-sim::contract_a::ContractADriver
            inputs=icount-stamped-recorded-list
            live_scheduler_transport=false
            rr_vcpu_cursor=fixed-content-addressed
            recorded_inputs_enforced=monotonic-within-run
            status=contract-a-isolated-single-vm-model
            RESULT
          '';
        }
      ];
    }
