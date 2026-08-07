{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.schedulerWakeOrdering",
  taskIds ? ["T-SCHED-21"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  libSource = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/lib.rs;
  };
  shmem = import ./_crucible-shmem-source.nix {inherit lib;};
  shmemTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/tests/advance_ceiling_handoff.rs;
  };
  runCeilingTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/tests/scheduler_run_ceiling.rs;
  };
  qemuQuantum = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-qemu/src/quantum.rs;
  };
  schedulingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/08-scheduling.md;
  runCeilingGate = builtins.readFile ./phase3-scheduler-run-ceiling.nix;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/08-scheduling.md" schedulingDoc [
      {
        label = "T-SCHED-21 completion note";
        needle = "Completed by `checks.crucible.phase3.schedulerWakeOrdering`";
      }
      {
        label = "wake after inbox write requirement";
        needle = "wake after inbox write";
      }
      {
        label = "consistent ceiling inputs snapshot";
        needle = "consistent `(ceiling, pending-inputs)` snapshot";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmem [
      {
        label = "pending input publication type";
        needle = "pub struct PendingInputPublication";
      }
      {
        label = "scheduler wake publication type";
        needle = "pub struct SchedulerWakePublication";
      }
      {
        label = "combined publish API";
        needle = "pub fn publish_scheduler_inputs_and_ceiling";
      }
      {
        label = "borrowed inbox publish API";
        needle = "pub fn publish_scheduler_inbox_and_ceiling";
      }
      {
        label = "ceiling prevalidation before enqueue";
        needle = "self.slots[dst_index].validate_scheduler_ceiling(ceiling)?;";
      }
      {
        label = "pending input source validation";
        needle = "validate_pending_input_source(input_index, input.src_slot, &input.frame)?;";
      }
      {
        label = "capacity preflight before enqueue";
        needle = "self.preflight_scheduler_wake_capacity(&enqueue_plans)?;";
      }
      {
        label = "pending input enqueue";
        needle = ".enqueue(&mut self.frame_entries[plan.entry_range], frame)";
      }
      {
        label = "prevalidated ceiling publish after enqueue";
        needle = "let wake = self.slots[dst_index].publish_prevalidated_scheduler_ceiling(ceiling)?;";
      }
      {
        label = "ordered publication result";
        needle = "pending_input_count: pending_inputs.len()";
      }
      {
        label = "stale ceiling validation";
        needle = "fn validate_scheduler_ceiling";
      }
      {
        label = "ceiling release store";
        needle = ".store(ceiling.max_advance_icount, Ordering::Release);";
      }
      {
        label = "prevalidated final publish";
        needle = "fn publish_prevalidated_scheduler_ceiling";
      }
      {
        label = "wake signal release increment";
        needle = "let previous = self.wake_signal.fetch_add(1, Ordering::Release);";
      }
      {
        label = "futex wake after signal";
        needle = "let futex = self.futex_wake_nonprivate(1)?;";
      }
      {
        label = "scheduler wake error type";
        needle = "pub enum SchedulerWakePublicationError";
      }
      {
        label = "source mismatch error";
        needle = "FrameSourceMismatch";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "scheduler handoff adapter";
        needle = "pub fn publish_to_shmem_after_inputs";
      }
      {
        label = "adapter uses combined shmem API";
        needle = "region.publish_scheduler_inputs_and_ceiling(dst_slot, pending_inputs, ceiling)";
      }
      {
        label = "handoff error type";
        needle = "pub enum SchedulerRunCeilingHandoffError";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "handoff error export";
        needle = "SchedulerRunCeilingHandoffError";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/advance_ceiling_handoff.rs" shmemTest [
      {
        label = "single input before wake test";
        needle = "scheduler_wake_enqueues_pending_inputs_before_ceiling_and_futex_wake";
      }
      {
        label = "batched inputs single wake test";
        needle = "scheduler_wake_batches_pending_inputs_before_single_wake";
      }
      {
        label = "borrowed inbox handoff test";
        needle = "scheduler_wake_node_slot_borrowed_inbox_handoff_orders_input_ceiling_and_wake";
      }
      {
        label = "full inbox no wake test";
        needle = "scheduler_wake_rejects_full_inbox_before_ceiling_or_wake";
      }
      {
        label = "source mismatch no wake test";
        needle = "scheduler_wake_rejects_source_mismatch_before_inbox_write_or_wake";
      }
      {
        label = "stale ceiling no inbox write test";
        needle = "scheduler_wake_rejects_stale_ceiling_before_inbox_write_or_wake";
      }
      {
        label = "source order test";
        needle = "scheduler_wake_publication_source_orders_inbox_before_ceiling_before_wake";
      }
    ]
    ++ failuresFor "crates/crucible/tests/scheduler_run_ceiling.rs" runCeilingTest [
      {
        label = "scheduler adapter regression";
        needle = "published_ceiling_writes_pending_inputs_before_futex_wake";
      }
      {
        label = "scheduler adapter call";
        needle = ".publish_to_shmem_after_inputs(&mut region, dst_slot, &pending)";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/quantum.rs" qemuQuantum [
      {
        label = "QEMU imports wake publication error";
        needle = "SchedulerWakePublicationError";
      }
      {
        label = "QEMU production ordered handoff call";
        needle = ".publish_scheduler_inbox_and_ceiling(";
      }
      {
        label = "QEMU routes VM slot to handoff";
        needle = "self.config.vm_slot,";
      }
      {
        label = "QEMU routes router slot to handoff";
        needle = "self.config.router_slot,";
      }
      {
        label = "QEMU uses inbound ring";
        needle = "self.view.inbound_ring,";
      }
      {
        label = "QEMU uses inbound entries";
        needle = "self.view.inbound_entries,";
      }
      {
        label = "QEMU start source-order test";
        needle = "qemu_quantum_start_uses_ordered_scheduler_wake_handoff";
      }
      {
        label = "QEMU inbound source-order test";
        needle = "qemu_quantum_inbound_uses_ordered_scheduler_wake_handoff";
      }
      {
        label = "QEMU nonempty inbound helper";
        needle = "fn publish_inbound_entry_and_wake";
      }
      {
        label = "QEMU nonempty pending input batch";
        needle = "std::slice::from_ref(entry)";
      }
      {
        label = "QEMU wake publication error variant";
        needle = "QemuQuantumError::SchedulerWakePublication";
      }
    ]
    ++ failuresFor "tests/crucible/phase3-scheduler-run-ceiling.nix" runCeilingGate [
      {
        label = "run-ceiling result points to wake-ordering gate";
        needle = "wake_ordering=covered-by-checks.crucible.phase3.schedulerWakeOrdering";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes scheduler wake-ordering check";
        needle = "schedulerWakeOrdering = import ./phase3-scheduler-wake-ordering.nix";
      }
    ]
    ++ forbiddenFor "tests/crucible/phase3-scheduler-run-ceiling.nix" runCeilingGate [
      {
        label = "stale deferred wake ordering result";
        needle = "wake_ordering=deferred-to-T-SCHED-21";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/advance_ceiling_handoff.rs" shmemTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 scheduler wake-ordering check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-scheduler-wake-ordering";
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
          name = "run-scheduler-wake-ordering";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-wake-ordering-target" \
              -p crucible-shmem \
              --test advance_ceiling_handoff \
              scheduler_wake \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-wake-ordering-target" \
              -p crucible \
              --features test-double \
              --test scheduler_run_ceiling \
              published_ceiling_writes_pending_inputs_before_futex_wake \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-scheduler-wake-ordering-target" \
              -p crucible-qemu \
              ordered_scheduler_wake_handoff \
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
            component=crucible-scheduler
            wake_ordering=inbox-before-ceiling-before-futex-wake
            pending_input_snapshot=release-acquire-spsc
            node_wake=release-wake_signal-non-private-futex
            RESULT
          '';
        }
      ];
    }
