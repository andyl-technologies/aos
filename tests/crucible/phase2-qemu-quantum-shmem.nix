{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuQuantumShmem",
  taskIds ? ["T-QEMU-12"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  quantumLib = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/quantum.rs;
    siblingTests = true;
  };
  # Production-only slice (everything before the `#[cfg(test)]` module): the
  # no-unwrap/no-expect forbids apply to production code; test code is allowed
  # panic shortcuts, matching the workspace clippy allow policy. `splitString`
  # treats its separator as a literal set of chars-to-split-on rather than a
  # regex only for single chars, so use replaceStrings to insert a unique
  # sentinel then split on it.
  quantumProd = builtins.head (
    lib.splitString "@@CFGTEST@@" (
      builtins.replaceStrings ["\n#[cfg(test)]"] ["@@CFGTEST@@"] quantumLib
    )
  );
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "completion note names shmem hot path";
        needle = "shared-memory hot path";
      }
      {
        label = "completion note points to completed injection contract";
        needle = "device-I/O freeze semantics are completed by";
      }
      {
        label = "completion note preserves async follow-up";
        needle = "real-time async wait remains tracked by";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "quantum module";
        needle = "mod quantum;";
      }
      {
        label = "quantum exports";
        needle = "pub use quantum::{";
      }
      {
        label = "hot-path adapter export";
        needle = "QemuQuantumShmemHotPath";
      }
      {
        label = "shmem-only assertion export";
        needle = "assert_qemu_quantum_hot_path_is_shmem_only";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/quantum.rs" quantumLib [
      {
        label = "module docs";
        needle = "QEMU per-quantum shared-memory hot path";
      }
      {
        label = "borrowed shared-memory view";
        needle = "pub struct QemuQuantumShmemView";
      }
      {
        label = "hot-path adapter";
        needle = "pub struct QemuQuantumShmemHotPath";
      }
      {
        label = "pending quantum token";
        needle = "pub struct QemuPendingQuantum";
      }
      {
        label = "existing node trait implementation";
        needle = "impl QemuShmemHotPathChannel for QemuQuantumShmemHotPath";
      }
      {
        label = "quantum start API";
        needle = "pub fn start_quantum";
      }
      {
        label = "quantum finish API";
        needle = "pub fn finish_quantum";
      }
      {
        label = "external node-slot binding";
        needle = "node_slot: &'a NodeSlot";
      }
      {
        label = "external inbound ring binding";
        needle = "inbound_ring: &'a RingHeader";
      }
      {
        label = "external outbound ring binding";
        needle = "outbound_ring: &'a RingHeader";
      }
      {
        label = "node report read operation";
        needle = "ReadNodeReport";
      }
      {
        label = "scheduler ceiling operation";
        needle = "StoreSchedulerCeiling";
      }
      {
        label = "futex wake operation";
        needle = "FutexWake";
      }
      {
        label = "plugin report observation operation";
        needle = "ObservePluginReport";
      }
      {
        label = "inbound SPSC frame enqueue";
        needle = "enqueue_inbound_frame";
      }
      {
        label = "outbound SPSC frame enqueue";
        needle = "enqueue_outbound_frame_from_plugin";
      }
      {
        label = "lookahead ceiling authorization";
        needle = "authorize_advance_ceiling";
      }
      {
        label = "scheduler ceiling store";
        needle = "publish_scheduler_ceiling";
      }
      {
        # Renamed: the wake publishes the inbound entry then wakes the slot.
        label = "frame wake";
        needle = "publish_inbound_entry_and_wake";
      }
      {
        # The host enqueues on the OUTBOUND ring and dequeues from the INBOUND
        # ring; the old needle had the ring direction inverted against the
        # current SPSC model.
        label = "SPSC outbound enqueue";
        needle = ".enqueue(self.view.outbound_entries";
      }
      {
        label = "SPSC inbound dequeue";
        needle = ".dequeue(self.view.inbound_entries)";
      }
      {
        label = "stale report rejection";
        needle = "PluginReportNotPublished";
      }
      {
        label = "shmem-only assertion";
        needle = "assert_qemu_quantum_hot_path_is_shmem_only";
      }
      {
        label = "forbidden plugin IPC plane";
        needle = "PluginIpcControlFrame";
      }
      {
        label = "forbidden QMP plane";
        needle = "QmpCommand";
      }
      {
        label = "ceiling cycle test";
        needle = "qemu_quantum_binds_external_shmem_and_finishes_after_plugin_report";
      }
      {
        label = "stale report test";
        needle = "qemu_quantum_rejects_finish_before_reaching_a_boundary";
      }
      {
        label = "idle report test";
        needle = "qemu_quantum_reports_idle_before_horizon";
      }
      {
        label = "lookahead rejection test";
        needle = "qemu_quantum_rejects_horizon_that_would_pass_possible_frame_delivery";
      }
      {
        label = "outbound frame test";
        needle = "qemu_quantum_drains_plugin_emitted_frames_toward_router";
      }
      {
        label = "forbidden plane test";
        needle = "qemu_quantum_hot_path_rejects_qmp_or_plugin_ipc_operations";
      }
      {
        label = "node trait test";
        needle = "qemu_quantum_implements_existing_shmem_hot_path_trait";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/quantum.rs" quantumProd [
      {
        label = "production unwrap";
        needle = ".unwrap()";
      }
      {
        label = "production expect";
        needle = ".expect(";
      }
      {
        label = "hard-coded host shell";
        needle = "/bin/sh";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu quantum shmem check";
        needle = "qemuQuantumShmem = import ./phase2-qemu-quantum-shmem.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu quantum-shmem check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-quantum-shmem";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.rust
        pkgs.sed
      ];

      cargoDeps = cargoDeps;

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
          name = "run-qemu-quantum-shmem";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-quantum-shmem-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              quantum::tests \
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
            attr_path=${attrPath}
            tasks=${taskList}
            qemu_36=implemented
            qemu_quantum_hot_path=shared-memory-only
            ceiling_cycle=report-current-icount,set-max-advance,futex-wake,observe-report
            frame_path=spsc-inbound-and-outbound
            qmp_per_quantum=forbidden
            plugin_ipc_per_quantum=forbidden
            exact_injection_contract=qemu-level
            bounded_async_wait_pending=T-QEMU-14
            rust_tests=crucible-qemu::quantum::tests
            RESULT
          '';
        }
      ];

      meta = {
        description = "Crucible Phase 2 QEMU per-quantum shared-memory hot-path gate";
      };
    }
