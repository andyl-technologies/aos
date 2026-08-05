{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.timeAdvanceCeiling",
  taskIds ? ["T-TIME-7"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoVendor {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-fWBTuyTXJ+/0BiVbB5WAtCqVwufg04NH4BJdocT+moU=";
  };

  shmemFrameNode =
    builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/frame_node/futex.rs;
  handoffTest = builtins.readFile ../../crates/crucible-shmem/tests/advance_ceiling_handoff.rs;
  scheduler = import ./_crucible-scheduler-source.nix {inherit lib;};
  timeSpec = builtins.readFile ../../docs/rfcs/0010-crucible/09-virtual-time-icount.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-shmem/src/shmem/frame_node.rs" shmemFrameNode [
      {
        label = "node slot ABI";
        needle = "pub struct NodeSlot";
      }
      {
        label = "current icount field";
        needle = "current_icount: AtomicU64";
      }
      {
        label = "derived current ns field";
        needle = "current_ns: AtomicU64";
      }
      {
        label = "max advance ceiling field";
        needle = "max_advance_icount: AtomicU64";
      }
      {
        label = "idle wake icount field";
        needle = "idle_wake_icount: AtomicU64";
      }
      {
        label = "wake signal futex word";
        needle = "wake_signal: AtomicU32";
      }
      {
        label = "publish generation";
        needle = "publish_gen: AtomicU32";
      }
      {
        label = "current icount offset constant";
        needle = "pub const NODE_SLOT_CURRENT_ICOUNT_OFFSET";
      }
      {
        label = "advance ceiling offset constant";
        needle = "pub const NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET";
      }
      {
        label = "128-byte node slot size";
        needle = "pub const NODE_SLOT_SIZE";
      }
      {
        label = "128-byte node slot alignment";
        needle = "pub const NODE_SLOT_ALIGN";
      }
      {
        label = "scheduler ceiling publisher";
        needle = "pub fn publish_scheduler_ceiling";
      }
      {
        label = "release ceiling store";
        needle = ".store(ceiling.max_advance_icount, Ordering::Release)";
      }
      {
        label = "node acquire ceiling load";
        needle = "self.max_advance_icount.load(Ordering::Acquire)";
      }
      {
        label = "node self-extension check";
        needle = "pub fn check_node_may_advance_to";
      }
      {
        label = "reached icount publisher";
        needle = "pub fn publish_reached_icount";
      }
      {
        label = "idle publish";
        needle = "pub fn publish_idle";
      }
      {
        label = "futex wait decision";
        needle = "pub enum FutexWait";
      }
      {
        label = "wake action";
        needle = "pub enum WakeAction";
      }
      {
        label = "cross-process futex marker";
        needle = "pub const FUTEX_PRIVATE: bool = false";
      }
      {
        label = "wake signal release increment";
        needle = "self.wake_signal.fetch_add(1, Ordering::Release)";
      }
      {
        label = "non-private futex wake wrapper";
        needle = "pub fn futex_wake_nonprivate";
      }
      {
        label = "non-private futex wait wrapper";
        needle = "pub fn futex_wait_nonprivate";
      }
      {
        label = "direct non-private futex wait syscall wrapper";
        needle = "pub fn futex_wait_word_nonprivate";
      }
      {
        label = "Linux futex wake operation";
        needle = "libc::FUTEX_WAKE";
      }
      {
        label = "Linux futex wait operation";
        needle = "libc::FUTEX_WAIT";
      }
      {
        label = "icount to virtual ns helper";
        needle = "pub fn icount_to_virtual_ns";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/src/shmem/frame_node.rs" shmemFrameNode [
      {
        label = "public raw advance ceiling field";
        needle = "pub max_advance_icount: AtomicU64";
      }
      {
        label = "public raw wake signal field";
        needle = "pub wake_signal: AtomicU32";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/advance_ceiling_handoff.rs" handoffTest [
      {
        label = "layout test";
        needle = "node_slot_layout_matches_wire_contract";
      }
      {
        label = "publish ceiling test";
        needle = "scheduler_publishes_ceiling_and_node_publishes_reached_icount";
      }
      {
        label = "running status generation test";
        needle = "mark_running_participates_in_publish_generation";
      }
      {
        label = "self extension rejection test";
        needle = "node_cannot_self_extend_past_published_ceiling";
      }
      {
        label = "futex no lost wake test";
        needle = "idle_publish_uses_race_free_futex_wait_and_wake_counter";
      }
      {
        label = "about-to-wait no lost wake test";
        needle = "scheduler_raise_during_idle_publish_race_bumps_wake_counter";
      }
      {
        label = "real Linux futex wrapper test";
        needle = "linux_non_private_futex_syscalls_are_available";
      }
      {
        label = "direct futex wait syscall test";
        needle = "futex_wait_word_nonprivate";
      }
      {
        label = "frame wake signal test";
        needle = "frame_delivery_wake_always_bumps_the_futex_word";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler.rs" scheduler [
      {
        label = "horizon ceiling conversion uses ceil timeline helper";
        needle = "ceiling: timeline.max_advance_icount_for_horizon(virtual_time)?";
      }
      {
        label = "timeline ceiling helper uses fixed-shift ceil conversion";
        needle = "horizon.to_icount_ceil(self.shift)";
      }
      {
        label = "scheduler horizon ceiling field";
        needle = "ceiling: Icount,";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/09-virtual-time-icount.md" timeSpec [
      {
        label = "T-TIME-7 live completion evidence";
        needle = "Completed by `checks.crucible.phase2.qemuLivePluginQuantum`";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes time advance ceiling check";
        needle = "timeAdvanceCeiling = import ./phase1-time-advance-ceiling.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 time-advance-ceiling check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-time-advance-ceiling";
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
          name = "run-time-advance-ceiling-tests";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-time-advance-ceiling-target" \
              -p crucible-shmem \
              --test advance_ceiling_handoff \
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
            status=partial
            evidence_scope=shmem-ceiling-and-handoff-model
            gate=gate:layer0-determinism
            gate=gate:layer1-injection
            gate=gate:scheduler-liveness
            gate=gate:abi-conformance
            node_slot_current_icount=true
            node_slot_current_ns=true
            max_advance_icount_release_store=true
            node_ceiling_acquire_load=true
            reached_icount_release_publish=true
            futex_wake_signal=true
            linux_non_private_futex_syscall=true
            futex_private=false
            no_lost_wake_about_to_wait=true
            node_self_extends_past_ceiling=false
            horizon_to_ceiling_conversion=ceil
            RESULT
          '';
        }
      ];
    }
