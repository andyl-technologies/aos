{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemControlFlags",
  taskIds ? ["T-SHM-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  controlTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/tests/control_flags.rs;
  };
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "pause request API";
        needle = "pub fn request_pause";
      }
      {
        label = "pause flag release store";
        needle = "self.pause_requested.store(1, Ordering::Release);";
      }
      {
        label = "shutdown request API";
        needle = "pub fn request_shutdown";
      }
      {
        label = "shutdown flag release store";
        needle = "self.shutdown_requested.store(1, Ordering::Release);";
      }
      {
        label = "control action observer";
        needle = "pub fn control_action(&self) -> RegionControlAction";
      }
      {
        label = "shutdown acquire load";
        needle = "self.shutdown_requested.load(Ordering::Acquire) != 0";
      }
      {
        label = "pause acquire load";
        needle = "self.pause_requested.load(Ordering::Acquire) != 0";
      }
      {
        label = "control action enum";
        needle = "pub enum RegionControlAction";
      }
      {
        label = "shutdown priority";
        needle = "RegionControlAction::Shutdown";
      }
      {
        label = "wake-all result";
        needle = "pub struct WakeAllResult";
      }
      {
        label = "wake-all helper";
        needle = "fn wake_all_slots_for_control";
      }
      {
        label = "wake every slot";
        needle = "for (slot_index, slot) in slots.into_iter().enumerate()";
      }
      {
        label = "control wake increments futex word";
        needle = ".wake_after_signal_increment()";
      }
      {
        label = "pause quiescence publisher";
        needle = "pub fn publish_pause_quiesced";
      }
      {
        label = "node done marker";
        needle = "pub fn mark_done(&self)";
      }
      {
        label = "done status release store";
        needle = "self.status.store(STATUS_DONE, Ordering::Release);";
      }
      {
        label = "control error type";
        needle = "pub enum RegionControlError";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/control_flags.rs" controlTest [
      {
        label = "pause flag wake-all test";
        needle = "pause_request_sets_flag_and_wakes_every_slot";
      }
      {
        label = "shutdown priority and done test";
        needle = "shutdown_request_takes_priority_and_nodes_mark_done";
      }
      {
        label = "pause quiescence test";
        needle = "node_can_publish_pause_quiescence_at_quantum_boundary";
      }
      {
        label = "Linux wake-all parked waiters test";
        needle = "linux_shutdown_request_wakes_all_parked_waiters";
      }
      {
        label = "off-Linux no-op wake-all test";
        needle = "off_linux_control_wake_all_uses_noop_futex_results";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/control_flags.rs" controlTest [
      {
        label = "ignored control flag test";
        needle = "#[ignore";
      }
      {
        label = "placeholder panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/13-shmem-abi.md" shmemSpec [
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes shmem control flags check";
        needle = "shmemControlFlags = import ./phase2-shmem-control-flags.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 shmem control flags check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-control-flags";
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
          name = "run-shmem-control-flags";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-control-flags-target" \
              -p crucible-shmem \
              --test control_flags \
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
            rust_tests=crucible-shmem::control_flags
            pause_requested=release_store
            shutdown_requested=release_store
            control_observation=acquire_load
            wake_all=non_private_futex
            RESULT
          '';
        }
      ];
    }
