{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.timeMultiVcpuAggregateClock",
  taskIds ? ["T-TIME-9"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  contractA = builtins.readFile ../../crates/crucible-sim/src/contract_a.rs;
  contractATests = builtins.readFile ../../crates/crucible-sim/tests/contract_a.rs;
  deadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  harnessObservation = builtins.readFile ../../crates/crucible-harness/src/fingerprint/observation.rs;
  phase0S11 = builtins.readFile ./phase0-s11.nix;
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  decisionRegister = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-sim/src/contract_a.rs" contractA [
      {
        label = "node-icount RR quantum getter";
        needle = "pub fn rr_switch_quantum(&self) -> u64";
      }
      {
        label = "RR quantum in content hash";
        needle = "hasher.write_u64(self.rr_switch_quantum);";
      }
      {
        label = "vCPU count in content hash";
        needle = "hasher.write_u64(self.vcpu_count);";
      }
      {
        label = "aggregate icount RR cursor helper";
        needle = "fn vcpu_for_icount(config: &ContractAConfig, aggregate_icount: u64) -> u64";
      }
      {
        label = "RR cursor uses node-icount quantum";
        needle = "(aggregate_icount / config.rr_switch_quantum) % config.vcpu_count";
      }
      {
        label = "virtual time uses aggregate icount";
        needle = "virtual_time_for_icount(aggregate_icount, config.icount_shift)";
      }
      {
        label = "run carries aggregate time trajectory";
        needle = "pub time_trajectory: Vec<TimeTrajectorySample>";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/contract_a.rs" contractATests [
      {
        label = "single aggregate time axis test";
        needle = "contract_a_multi_vcpu_uses_single_aggregate_time_axis";
      }
      {
        label = "RR quantum content-addressing test";
        needle = "contract_a_rr_switch_quantum_is_content_addressed_node_icount_units";
      }
      {
        label = "aggregate cursor proof";
        needle = "vec![0, 0, 1, 1, 2, 2, 0]";
      }
      {
        label = "RR quantum changes interleaving";
        needle = "vec![0, 0, 0, 1, 1, 1, 2]";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/deadline.rs" deadline [
      {
        label = "per-vCPU deadline report";
        needle = "pub struct PerVcpuDeadlineReport";
      }
      {
        label = "multi-vCPU deadline reducer";
        needle = "pub fn aggregate_multi_vcpu_deadline";
      }
      {
        label = "deadline reducer validates expected vCPU count";
        needle = "vcpu_count: u64";
      }
      {
        label = "minimum armed deadline accumulator";
        needle = "min_deadline_ns";
      }
      {
        label = "zero vCPU count rejection";
        needle = "ZeroVcpuDeadlineCount";
      }
      {
        label = "empty vCPU report rejection";
        needle = "EmptyVcpuDeadlineSet";
      }
      {
        label = "out-of-range vCPU report rejection";
        needle = "VcpuDeadlineOutOfRange";
      }
      {
        label = "duplicate vCPU report rejection";
        needle = "DuplicateVcpuDeadline";
      }
      {
        label = "missing vCPU report rejection";
        needle = "MissingVcpuDeadline";
      }
      {
        label = "minimum armed virtual deadline test";
        needle = "multi_vcpu_deadline_uses_minimum_armed_virtual_deadline";
      }
      {
        label = "no armed timer aggregate test";
        needle = "multi_vcpu_deadline_returns_no_armed_timer_when_every_vcpu_is_idle";
      }
      {
        label = "duplicate report aggregate test";
        needle = "multi_vcpu_deadline_rejects_duplicate_vcpu_reports";
      }
      {
        label = "empty report aggregate test";
        needle = "multi_vcpu_deadline_rejects_empty_report_sets";
      }
      {
        label = "zero vCPU count aggregate test";
        needle = "multi_vcpu_deadline_rejects_zero_expected_vcpus";
      }
      {
        label = "out-of-range report aggregate test";
        needle = "multi_vcpu_deadline_rejects_out_of_range_vcpu_reports";
      }
      {
        label = "incomplete report aggregate test";
        needle = "multi_vcpu_deadline_rejects_incomplete_vcpu_report_sets";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "deadline reducer exported";
        needle = "aggregate_multi_vcpu_deadline";
      }
      {
        label = "per-vCPU deadline report exported";
        needle = "PerVcpuDeadlineReport";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/fingerprint/observation.rs" harnessObservation [
      {
        label = "per-vCPU retired counts restricted to fingerprint observation";
        needle = "pub struct VcpuRetiredCount";
      }
      {
        label = "RR scheduler state fingerprints per-vCPU counts";
        needle = "pub struct RrSchedulerState";
      }
      {
        label = "per-vCPU counts are fingerprint fields";
        needle = "per_vcpu_retired";
      }
    ]
    ++ failuresFor "tests/crucible/phase0-s11.nix" phase0S11 [
      {
        label = "multi-vCPU spike pins RR quantum";
        needle = "rr_switch_quantum=\"$RR_SWITCH_QUANTUM\"";
      }
      {
        label = "multi-vCPU spike proves aggregate icount stream";
        needle = "aggregate_icount_stream_match=true";
      }
      {
        label = "multi-vCPU spike fingerprints per-vCPU counts";
        needle = "register_count_assertion=nonempty_per_vcpu";
      }
      {
        label = "multi-vCPU spike pins the predeclared S11 horizon";
        needle = "stopAt ? 4000000000";
      }
      {
        label = "multi-vCPU spike sustains four-thread contention";
        needle = ''puts("CRUCIBLE_S11_SUSTAIN_ACTIVE threads=4 mode=spinlock")'';
      }
      {
        label = "multi-vCPU spike executes horizon/plugin-exit register comparison";
        needle = ''[ "$horizon_register_hash" = "$final_register_hash" ]'';
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
      {
        label = "TIME-24 multi-vCPU deadline minimum";
        needle = "minimum over all vCPUs' armed virtual-clock";
      }
      {
        label = "TIME-34 aggregate node clock";
        needle = "retired-instruction count across all `N` vCPUs";
      }
      {
        label = "TIME-35 node-icount RR quantum";
        needle = "in **node-icount units**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/31-decision-register.md" decisionRegister [
      {
        label = "single aggregate icount decision";
        needle = "single aggregate icount";
      }
      {
        label = "RR quantum default decision";
        needle = "rr_switch_quantum=4096";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes multi-vCPU aggregate clock check";
        needle = "timeMultiVcpuAggregateClock = import ./phase1-time-multi-vcpu-aggregate-clock.nix";
      }
      {
        label = "layer0 gate lists T-TIME-9";
        needle = "\"T-TIME-9\"";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "per-vCPU shared-memory field";
        needle = "per_vcpu";
      }
      {
        label = "per-vCPU shared-memory slot";
        needle = "VcpuSlot";
      }
      {
        label = "per-vCPU deadline shared-memory field";
        needle = "vcpu_deadline";
      }
      {
        label = "per-vCPU shift shared-memory field";
        needle = "vcpu_shift";
      }
      {
        label = "per-vCPU epoch shared-memory field";
        needle = "vcpu_epoch";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 multi-vCPU aggregate clock check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-time-multi-vcpu-aggregate-clock";
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
          name = "run-multi-vcpu-aggregate-clock";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-multi-vcpu-aggregate-clock-target" \
              -p crucible-sim \
              --test contract_a \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-multi-vcpu-aggregate-clock-target" \
              -p crucible-qemu-plugin \
              --lib \
              multi_vcpu_deadline \
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
            evidence_scope=multi-vcpu-clock-model
            gate=gate:layer0-determinism
            gate=gate:single-vm-fingerprint
            aggregate_node_clock=true
            node_clock_source=aggregate_retired_instructions
            per_vcpu_counts_surface=execution-fingerprint-only
            per_vcpu_shmem_fields=false
            rr_switch_quantum_units=node-icount
            rr_switch_quantum_content_addressed=true
            multi_vcpu_deadline=min-armed-vcpu-deadline
            RESULT
          '';
        }
      ];
    }
