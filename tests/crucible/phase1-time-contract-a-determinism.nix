{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.timeContractADeterminism",
  taskIds ? ["T-TIME-8"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  contractA = builtins.readFile ../../crates/crucible-sim/src/contract_a.rs;
  contractATests = builtins.readFile ../../crates/crucible-sim/tests/contract_a.rs;
  simGate = builtins.readFile ../../crates/crucible-sim/tests/gate_layer0_determinism.rs;
  model = import ./_crucible-model-source.nix {inherit lib;};
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  pluginDeadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  pluginTimeControl = import ./_qemu-plugin-time-control-source.nix {inherit lib;};
  qemuLaunch = builtins.readFile ../../crates/crucible-qemu/src/launch.rs;
  harnessLint = builtins.readFile ./phase1-harness-lint.nix;
  clippyConfig = builtins.readFile ../../crates/clippy.toml;
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  hostTimeReadBan = [
    {
      label = "std time module";
      needle = "std::time";
    }
    {
      label = "host monotonic now";
      needle = "Instant::now";
    }
    {
      label = "host elapsed time";
      needle = "Instant::elapsed";
    }
    {
      label = "host wall-clock now";
      needle = "SystemTime::now";
    }
    {
      label = "host wall-clock epoch";
      needle = "UNIX_EPOCH";
    }
    {
      label = "tokio host timer";
      needle = "tokio::time";
    }
    {
      label = "host thread sleep";
      needle = "thread::sleep";
    }
  ];

  timePathHostTimeFailures =
    lib.concatMap (
      source:
        forbiddenFor source.label source.content hostTimeReadBan
    ) [
      {
        label = "crates/crucible-sim/src/contract_a.rs";
        content = contractA;
      }
      {
        label = "crates/crucible/src/model.rs";
        content = model;
      }
      {
        label = "crates/crucible/src/scheduler.rs";
        content = scheduler;
      }
      {
        label = "crates/crucible-shmem/src/lib.rs";
        content = shmemLib;
      }
      {
        label = "crates/crucible-qemu-plugin/src/deadline.rs";
        content = pluginDeadline;
      }
      {
        label = "crates/crucible-qemu-plugin/src/time_control.rs";
        content = pluginTimeControl;
      }
      {
        label = "crates/crucible-qemu/src/launch.rs";
        content = qemuLaunch;
      }
    ];

  failures =
    failuresFor "crates/crucible-sim/src/contract_a.rs" contractA [
      {
        label = "default fixed icount shift";
        needle = "pub const DEFAULT_CONTRACT_A_ICOUNT_SHIFT";
      }
      {
        label = "maximum shift guard";
        needle = "pub const MAX_CONTRACT_A_ICOUNT_SHIFT";
      }
      {
        label = "explicit shift constructor";
        needle = "pub fn new_with_icount_shift";
      }
      {
        label = "config shift getter";
        needle = "pub fn icount_shift(&self) -> u8";
      }
      {
        label = "time trajectory sample";
        needle = "pub struct TimeTrajectorySample";
      }
      {
        label = "time fingerprint fields";
        needle = "pub struct ContractATimeFingerprint";
      }
      {
        label = "run carries time trajectory";
        needle = "pub time_trajectory: Vec<TimeTrajectorySample>";
      }
      {
        label = "run carries time fingerprint";
        needle = "pub time_fingerprint: ContractATimeFingerprint";
      }
      {
        label = "icount-derived projection helper";
        needle = "fn virtual_time_for_icount";
      }
      {
        label = "time-only fingerprint helper";
        needle = "fn time_fingerprint";
      }
      {
        label = "run fingerprint includes time-derived fields";
        needle = "time_fingerprint.write_hash_material(&mut hasher);";
      }
      {
        label = "overflow rejection";
        needle = "VirtualTimeOverflow";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/contract_a.rs" contractATests [
      {
        label = "pure shift trajectory test";
        needle = "contract_a_time_trajectory_is_pure_icount_shift_function";
      }
      {
        label = "adversarial host condition test";
        needle = "contract_a_time_fingerprint_matches_across_adversarial_host_conditions";
      }
      {
        label = "host condition profiles";
        needle = "AdversarialHostProfile";
      }
      {
        label = "time-only fingerprint payload independence";
        needle = "contract_a_time_fingerprint_ignores_payload_when_icount_horizon_is_fixed";
      }
      {
        label = "virtual time overflow test";
        needle = "contract_a_driver_rejects_unrepresentable_virtual_time";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/gate_layer0_determinism.rs" simGate [
      {
        label = "layer0 gate asserts time trajectory";
        needle = "first.time_trajectory.len()";
      }
      {
        label = "layer0 gate asserts time fingerprint";
        needle = "first.time_fingerprint.final_virtual_time_ns";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-harness-lint.nix" harnessLint [
      {
        label = "harness lint bans Instant::now";
        needle = "std::time::Instant::now";
      }
      {
        label = "harness lint bans Instant::elapsed";
        needle = "std::time::Instant::elapsed";
      }
      {
        label = "harness lint bans SystemTime::now";
        needle = "std::time::SystemTime::now";
      }
    ]
    ++ failuresFor "crates/clippy.toml" clippyConfig [
      {
        label = "clippy bans Instant::now";
        needle = "std::time::Instant::now";
      }
      {
        label = "clippy bans Instant::elapsed";
        needle = "std::time::Instant::elapsed";
      }
      {
        label = "clippy bans SystemTime::now";
        needle = "std::time::SystemTime::now";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes Contract A time determinism check";
        needle = "timeContractADeterminism = import ./phase1-time-contract-a-determinism.nix";
      }
    ]
    ++ timePathHostTimeFailures;
in
  if failures != []
  then throw "crucible phase1 Contract A time determinism check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-time-contract-a-determinism";
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
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
          '';
        }
        {
          name = "run-contract-a-time-determinism";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-contract-a-determinism-target" \
              -p crucible-sim \
              --test contract_a \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-contract-a-determinism-target" \
              -p crucible-sim \
              --test gate_layer0_determinism \
              gate_layer0_determinism_reduces_fixed_contract_a_twice \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            open_tasks=${builtins.concatStringsSep "," openTaskIds}
            status=complete
            evidence_scope=contract-a-simulation-model
            gate=gate:layer0-determinism
            gate=gate:single-vm-fingerprint
            contract_a_single_node=true
            time_trajectory=icount_shift_pure_function
            time_fingerprint_fields=final_icount,final_virtual_time_ns,trajectory_digest,time_derived_fields_digest
            host_adversary=speed-load-scheduling-cores-excluded
            recorded_input_trajectory=boot-network-timer
            host_time_reads_on_time_path=false
            RESULT
          '';
        }
      ];
    }
