{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemMultiVcpuNodeSlot",
  taskIds ? ["T-SHM-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  shmemContract = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-shmem/src/lib.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/layout.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/runtime.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs)
    (builtins.readFile ../../crates/crucible-shmem/src/shmem/region/layout.rs)
  ];
  generatedHeader = builtins.readFile ../../crates/crucible-shmem/include/crucible_shmem_abi.h;
  multiVcpuTest = builtins.readFile ../../crates/crucible-shmem/tests/multi_vcpu_node_slot.rs;
  deadline = builtins.readFile ../../crates/crucible-qemu-plugin/src/deadline.rs;
  fingerprintObservation = builtins.readFile ../../crates/crucible-harness/src/fingerprint/observation.rs;
  timeGate = builtins.readFile ./phase1-time-multi-vcpu-aggregate-clock.nix;
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  decisionRegister = builtins.readFile ../../docs/rfcs/0010-crucible/31-decision-register.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  perVcpuShmemForbidden = [
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
    {
      label = "vCPU-counted shared-memory region shape";
      needle = "vcpu_count";
    }
  ];

  failures =
    failuresFor "crates/crucible-shmem source modules" shmemContract [
      {
        label = "ABI version unchanged for multi-vCPU nodes";
        needle = "pub const ABI_VERSION: u32 = 17;";
      }
      {
        label = "region config uses VM node count";
        needle = "pub vm_node_count: u32,";
      }
      {
        label = "region layout physical slot count";
        needle = "node_count: MAX_NODES as u32,";
      }
      {
        label = "ring count derived from VM nodes only";
        needle = "config.vm_node_count";
      }
      {
        label = "single node slot struct";
        needle = "pub struct NodeSlot";
      }
      {
        label = "aggregate current icount field";
        needle = "current_icount: AtomicU64";
      }
      {
        label = "aggregate ceiling field";
        needle = "max_advance_icount: AtomicU64";
      }
      {
        label = "aggregate idle wake field";
        needle = "idle_wake_icount: AtomicU64";
      }
      {
        label = "node-scoped device I/O flag";
        needle = "device_io_active: AtomicU8";
      }
      {
        label = "aggregate idle publisher";
        needle = "pub fn publish_idle(";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem source modules" shmemContract perVcpuShmemForbidden
    ++ failuresFor "crates/crucible-shmem/include/crucible_shmem_abi.h" generatedHeader [
      {
        label = "C node slot declaration";
        needle = "crucible_shmem_node_slot";
      }
      {
        label = "C node slot aggregate current icount offset";
        needle = "CRUCIBLE_SHMEM_NODE_SLOT_CURRENT_ICOUNT_OFFSET 0u";
      }
      {
        label = "C node slot aggregate ceiling offset";
        needle = "CRUCIBLE_SHMEM_NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET 16u";
      }
      {
        label = "C node slot aggregate idle wake offset";
        needle = "CRUCIBLE_SHMEM_NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET 24u";
      }
      {
        label = "C node-scoped device I/O flag offset";
        needle = "CRUCIBLE_SHMEM_NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET 38u";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/include/crucible_shmem_abi.h" generatedHeader perVcpuShmemForbidden
    ++ failuresFor "crates/crucible-shmem/tests/multi_vcpu_node_slot.rs" multiVcpuTest [
      {
        label = "multi-vCPU shape invariance test";
        needle = "multi_vcpu_count_does_not_change_region_shape_or_abi_version";
      }
      {
        label = "single slot aggregate clock/deadline test";
        needle = "one_node_slot_carries_aggregate_multi_vcpu_clock_and_idle_deadline";
      }
      {
        label = "no per-vCPU shmem fields test";
        needle = "shmem_abi_has_no_per_vcpu_fields_or_slots";
      }
      {
        label = "generated header node-scoped test";
        needle = "generated_c_header_keeps_node_slot_node_scoped";
      }
      {
        label = "aggregate deadline minimum modeled";
        needle = "per_vcpu_deadlines.iter().min()";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/multi_vcpu_node_slot.rs" multiVcpuTest [
      {
        label = "ignored multi-vCPU shmem ABI test";
        needle = "#[ignore";
      }
      {
        label = "placeholder panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/deadline.rs" deadline [
      {
        label = "multi-vCPU deadline reducer";
        needle = "pub fn aggregate_multi_vcpu_deadline";
      }
      {
        label = "minimum armed deadline accumulator";
        needle = "min_deadline_ns";
      }
      {
        label = "per-vCPU deadline reports stay plugin-side";
        needle = "pub struct PerVcpuDeadlineReport";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/fingerprint/observation.rs" fingerprintObservation [
      {
        label = "per-vCPU register state is fingerprint observation";
        needle = "pub struct VcpuRegisterDigest";
      }
      {
        label = "per-vCPU retired counts are fingerprint observation";
        needle = "pub struct VcpuRetiredCount";
      }
      {
        label = "RR scheduler state fingerprints per-vCPU counts";
        needle = "pub struct RrSchedulerState";
      }
      {
        label = "per-vCPU counts remain in fingerprint material";
        needle = "per_vcpu_retired";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-time-multi-vcpu-aggregate-clock.nix" timeGate [
      {
        label = "phase1 gate forbids per-vCPU shmem field";
        needle = "per-vCPU shared-memory field";
      }
      {
        label = "phase1 gate proves aggregate deadline reducer";
        needle = "aggregate_multi_vcpu_deadline";
      }
      {
        label = "phase1 gate proves per-vCPU fingerprint boundary";
        needle = "per_vcpu_retired";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
      {
        label = "multi-vCPU aggregate node clock";
        needle = "retired-instruction count across all `N` vCPUs";
      }
      {
        label = "per-vCPU counts plugin-internal";
        needle = "Per-vCPU retired counts are";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/31-decision-register.md" decisionRegister [
      {
        label = "decision says no per-vCPU shmem slots";
        needle = "no per-vCPU shmem";
      }
      {
        label = "decision says no per-vCPU clocks";
        needle = "no per-vCPU clocks";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes shmem multi-vCPU node slot check";
        needle = "shmemMultiVcpuNodeSlot = import ./phase2-shmem-multi-vcpu-node-slot.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 shmem multi-vCPU node slot check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-multi-vcpu-node-slot";
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
          name = "run-shmem-multi-vcpu-node-slot";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-multi-vcpu-node-slot-target" \
              -p crucible-shmem \
              --test multi_vcpu_node_slot \
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
            gate=gate:abi-conformance
            tasks=${taskList}
            abi_version=unchanged
            shmem_slots=node_scoped
            node_slot_fields=aggregate_current_icount,aggregate_ceiling,aggregate_idle_wake,device_io_active
            per_vcpu_state=fingerprint_observation_not_shmem
            RESULT
          '';
        }
      ];
    }
