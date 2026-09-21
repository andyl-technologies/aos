{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuExactSnapshotRestore",
  taskIds ? ["T-QEMU-5"],
  checkpointDeltaFlight ?
    import ./phase2-qemu-checkpoint-delta-flight.nix {
      inherit pkgs lib;
    },
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  exactRestoreReachability = import ./phase2-qemu-exact-restore-reachability.nix {
    inherit pkgs lib;
  };
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  busySmpGuest = import ./phase2-qemu-live-plugin-quantum-smp-guest.nix {
    inherit pkgs;
    guestVcpus = 2;
    guestIdle = false;
    startAps = false;
  };
  blockInitramfs = import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};
  qemuCheckpoint = builtins.readFile ../../crates/crucible-qemu/src/checkpoint.rs;
  qemuNode = builtins.readFile ../../crates/crucible-qemu/src/node.rs;
  qemuNodeExactSnapshot = builtins.readFile ../../crates/crucible-qemu/src/node/exact_snapshot.rs;
  qemuNodeExactSnapshotCapture =
    builtins.readFile ../../crates/crucible-qemu/src/node/exact_snapshot/capture.rs;
  qemuNodeFactory = builtins.readFile ../../crates/crucible-qemu/src/node_factory.rs;
  qemuExactRestoreAdmission = builtins.concatStringsSep "\n" [
    (builtins.readFile ../../crates/crucible-qemu/src/realization.rs)
    (builtins.readFile ../../crates/crucible-qemu/src/realization/node_executor.rs)
    (builtins.readFile ../../crates/crucible-qemu/src/realization/node_executor/admission.rs)
  ];
  smpGuestSource = builtins.readFile ./phase2-qemu-live-plugin-quantum-smp-guest.nix;
  productionLoop = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/quantum_loop.rs;
  productionRuntime = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle.rs;
  productionConstruction = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/construction.rs;
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "crates/crucible-qemu/src/checkpoint.rs" qemuCheckpoint [
      {
        label = "host-I/O checkpoint";
        needle = "pub struct QemuHostIoCheckpoint";
      }
      {
        label = "block continuation";
        needle = "Option<QemuLiveBlockIoServicerCheckpoint>";
      }
      {
        label = "node continuation";
        needle = "pub struct QemuNodeContinuationCheckpoint";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node/exact_snapshot.rs" qemuNodeExactSnapshot [
      {
        label = "descriptor-retaining exact capture result";
        needle = "pub struct QemuExactCheckpointCaptureResult";
      }
      {
        label = "pinned output descriptor access";
        needle = "pub fn output_files_mut";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node/exact_snapshot/capture.rs" qemuNodeExactSnapshotCapture [
      {
        label = "admission-bound coordinated capture";
        needle = "fn capture_admitted_exact_checkpoint";
      }
      {
        label = "capture admission identity check";
        needle = "validate_capture_admission_binding(";
      }
      {
        label = "node-addressed icount validation";
        needle = "checkpoint.node_icounts.get(node)";
      }
      {
        label = "live boundary icount validation";
        needle = "let observed_icount = self.current_icount()?";
      }
      {
        label = "host capture before VMState";
        needle = ".checkpoint_host_io(checkpoint.id)";
      }
      {
        label = "opaque aggregate snapshot";
        needle = "QemuVmSnapshot::from_live_capture";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {
        label = "forced crash gate";
        needle = "force_crash_and_reap_for_gate";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/node_factory.rs" qemuNodeFactory [
      {
        label = "host prevalidation";
        needle = ".validate_host_io_checkpoint(checkpoint.id, host_io_checkpoint)";
      }
      {
        label = "descriptor-backed checkpoint restore";
        needle = ".restore_exact_checkpoint(exact_checkpoint.request)";
      }
      {
        label = "host continuation commit";
        needle = ".restore_host_io_checkpoint(checkpoint.id, host_io_checkpoint)";
      }
      {
        label = "node continuation commit";
        needle = "node.restore_node_continuation(node_continuation)";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-live-plugin-quantum-smp-guest.nix" smpGuestSource [
      {
        label = "selectable busy guest";
        needle = "guestIdle ? true,";
      }
      {
        label = "busy BSP";
        needle = "bsp_busy:";
      }
      {
        label = "busy application processor";
        needle = "ap_busy:";
      }
      {
        label = "halted AP selection";
        needle = "startAps ? true,";
      }
      {
        label = "busy BSP and halted AP evidence";
        needle = ''else "bsp-busy-aps-halted";'';
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle/quantum_loop.rs" productionLoop [
      {
        label = "snapshot control boundary capture";
        needle = "self.capture_exact_checkpoint_set(&configuration)?";
      }
      {
        label = "running-node publication capture";
        needle = ".capture_exact_checkpoint_for_publication_guarded(";
      }
      {
        label = "powered-off paused capture";
        needle = ".capture_exact_checkpoint_paused_guarded(";
      }
      {
        label = "VMState artifact persistence";
        needle = "stage_open_checkpoint_artifact_chunks_with_boundary(";
      }
      {
        label = "pinned capture descriptor hashing";
        needle = "hash_exact_checkpoint_open_file_sha256_with_boundary(";
      }
      {
        label = "captured descriptor handoff";
        needle = "let (ram_file, device_file) = exact_capture.output_files_mut();";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle.rs" productionRuntime [
      {
        label = "artifact authentication";
        needle = "failed content authentication";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle/construction.rs" productionConstruction [
      {
        label = "restored fingerprint check";
        needle = "restored_fingerprint != expected_fingerprint";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu exact-restore admission sources" qemuExactRestoreAdmission [
      {
        label = "public exact-runtime minting";
        needle = "pub const fn authorize_exact_checkpoint_runtime";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU exact snapshot restore check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-exact-snapshot-restore";
      version = "0";
      src = crucibleSrc;
      buildDeps =
        [
          pkgs.coreutils
          pkgs.crucible-qemu-plugin
          pkgs.grep
          pkgs.qemu-crucible
          pkgs.rust
          pkgs.sed
          checkpointDeltaFlight
          exactRestoreReachability
        ]
        ++ dependencies;
      GUEST_KERNEL = "${busySmpGuest}/smp-idle-guest.elf";
      GUEST_KERNEL_IS_FILE = "1";
      DISKLESS_INITRD = "";
      BLOCK_INITRD = "${blockInitramfs}/initrd.img";
      GUEST_FIRMWARE = "${pkgs.qemu-crucible}/share/qemu/bios-256k.bin";
      GUEST_KERNEL_APPEND = "console=ttyS0 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off";
      CRUCIBLE_EXACT_TIMEOUT_SECS = "240";
      TASK_IDS = taskList;
      ATTR_PATH = attrPath;
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
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then cd source; fi
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
          name = "run-real-exact-snapshot";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then cd source; fi
            qemu_lib_tests="$TMPDIR/crucible-qemu-lib-tests"
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/exact-snapshot-target" \
              --manifest-path crates/Cargo.toml -p crucible-qemu --lib \
              -- --list > "$qemu_lib_tests"
            run_exact_qemu_test() {
              test_name="$1"
              grep -Fqx "$test_name: test" "$qemu_lib_tests"
              cargo test --frozen --offline \
                --target-dir "$TMPDIR/exact-snapshot-target" \
                --manifest-path crates/Cargo.toml -p crucible-qemu --lib \
                "$test_name" -- --exact --include-ignored --test-threads=1
            }
            run_exact_qemu_test \
              node::exact_snapshot::capture_admission_tests::capture_admission_rejects_another_modeled_node
            run_exact_qemu_test \
              node_factory::tests::factory_assembles_node_with_exact_snapshot_qmp_control

            grep -Fqx PASS "${checkpointDeltaFlight}/result"
            grep -Fqx 'patched_fixture_exercised=true' \
              "${checkpointDeltaFlight}/result"
            grep -Fqx 'checkpoint_restore_equal=true' \
              "${checkpointDeltaFlight}/result"
            grep -Fqx 'direct_delta_reconstruction_equal=true' \
              "${checkpointDeltaFlight}/result"
            mkdir -p "$out"
            {
              printf 'PASS\n'
              printf 'attr_path=%s\n' "$ATTR_PATH"
              printf 'task_ids=%s\n' "$TASK_IDS"
              printf 'scope=compiled-operation-specific-exact-checkpoint-admission\n'
              printf 'proven=identity-bound-admission,live-capture-and-restore,descriptor-backed-restore\n'
            } > "$out/result"
          '';
        }
      ];
    }
