{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemHandoffFutex",
  taskIds ? ["T-SHM-8" "T-SHM-9" "T-SHM-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  handoffTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/tests/advance_ceiling_handoff.rs;
  };
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "node slot ABI";
        needle = "pub struct NodeSlot";
      }
      {
        label = "scheduler-only ceiling publisher";
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
        label = "node-side advance check";
        needle = "pub fn check_node_may_advance_to";
      }
      {
        label = "reached icount publisher";
        needle = "pub fn publish_reached_icount";
      }
      {
        label = "idle precondition publisher";
        needle = "pub fn publish_idle";
      }
      {
        label = "publish generation seqlock";
        needle = "publish_gen: AtomicU32";
      }
      {
        label = "seqlock writer generation bump";
        needle = "self.publish_gen.fetch_add(1, Ordering::AcqRel)";
      }
      {
        label = "seqlock stable snapshot check";
        needle = "before == after && after.is_multiple_of(2)";
      }
      {
        label = "race-free futex wait decision";
        needle = "pub fn prepare_futex_wait";
      }
      {
        label = "wait validity re-check";
        needle = "pub fn futex_wait_still_valid";
      }
      {
        label = "non-private futex marker";
        needle = "pub const FUTEX_PRIVATE: bool = false";
      }
      {
        label = "release wake-signal bump";
        needle = "self.wake_signal.fetch_add(1, Ordering::Release)";
      }
      {
        label = "wake trigger helper";
        needle = "fn wake_after_signal_increment";
      }
      {
        label = "wake trigger issues futex wake";
        needle = "let futex = self.futex_wake_nonprivate(1)?;";
      }
      {
        label = "non-private wake wrapper";
        needle = "pub fn futex_wake_nonprivate";
      }
      {
        label = "non-private wait wrapper";
        needle = "pub fn futex_wait_nonprivate";
      }
      {
        label = "direct wait wrapper";
        needle = "pub fn futex_wait_word_nonprivate";
      }
      {
        label = "Linux FUTEX_WAKE operation";
        needle = "libc::FUTEX_WAKE";
      }
      {
        label = "Linux FUTEX_WAIT operation";
        needle = "libc::FUTEX_WAIT";
      }
      {
        label = "off-Linux wait no-op outcome";
        needle = "FutexWaitOutcome::Noop";
      }
      {
        label = "Linux woken wait outcome";
        needle = "FutexWaitOutcome::Woken";
      }
      {
        label = "off-Linux no-op wake result";
        needle = "Ok(FutexWakeResult";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "public raw advance ceiling field";
        needle = "pub max_advance_icount: AtomicU64";
      }
      {
        label = "private futex operation";
        needle = "FUTEX_PRIVATE_FLAG";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/advance_ceiling_handoff.rs" handoffTest [
      {
        label = "layout test";
        needle = "node_slot_layout_matches_wire_contract";
      }
      {
        label = "publish ceiling and icount test";
        needle = "scheduler_publishes_ceiling_and_node_publishes_reached_icount";
      }
      {
        label = "publish generation test";
        needle = "mark_running_participates_in_publish_generation";
      }
      {
        label = "self-extension rejection test";
        needle = "node_cannot_self_extend_past_published_ceiling";
      }
      {
        label = "race-free futex wait test";
        needle = "idle_publish_uses_race_free_futex_wait_and_wake_counter";
      }
      {
        label = "about-to-wait race test";
        needle = "scheduler_raise_during_idle_publish_race_bumps_wake_counter";
      }
      {
        label = "frame delivery wake trigger test";
        needle = "frame_delivery_wake_always_bumps_the_futex_word";
      }
      {
        label = "scheduler trigger wakes parked waiter test";
        needle = "linux_scheduler_trigger_wakes_parked_waiter";
      }
      {
        label = "frame trigger wakes parked waiter test";
        needle = "linux_frame_delivery_trigger_wakes_parked_waiter";
      }
      {
        label = "Linux non-private syscall test";
        needle = "linux_non_private_futex_syscalls_are_available";
      }
      {
        label = "off-Linux no-op shim test";
        needle = "off_linux_futex_syscalls_compile_to_noops";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes shmem handoff/futex check";
        needle = "shmemHandoffFutex = import ./phase2-shmem-handoff-futex.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 shmem handoff/futex check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-handoff-futex";
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
          name = "run-shmem-handoff-futex";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-handoff-futex-target" \
              -p crucible-shmem \
              --test advance_ceiling_handoff \
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
            gate=gate:layer1-injection
            gate=gate:abi-conformance
            rust_tests=crucible-shmem::advance_ceiling_handoff
            advance_ceiling=release-store-acquire-load
            publish_gen=seqlock
            futex=non-private
            wake_triggers=scheduler-ceiling,frame-delivery
            off_linux_futex=noop
            RESULT
          '';
        }
      ];
    }
