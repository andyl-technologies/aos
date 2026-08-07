{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuExactSnapshotRestore",
  taskIds ? ["T-QEMU-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };
  idleInitramfs = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  blockInitramfs = import ./phase2-qemu-live-block-io-guest.nix {inherit pkgs;};
  qemuCheckpoint = builtins.readFile ../../crates/crucible-qemu/src/checkpoint.rs;
  qemuNode = builtins.readFile ../../crates/crucible-qemu/src/node.rs;
  qemuNodeFactory = builtins.readFile ../../crates/crucible-qemu/src/node_factory.rs;
  qemuExactRunner = builtins.readFile ../../crates/crucible-qemu/examples/crucible-qemu-live-exact-snapshot.rs;
  productionLoop = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/quantum_loop.rs;
  productionRuntime = builtins.readFile ../../crates/crucible-api/src/vm_lifecycle/runtime.rs;
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "crates/crucible-qemu/src/checkpoint.rs" qemuCheckpoint [
      {label = "host-I/O checkpoint"; needle = "pub struct QemuHostIoCheckpoint";}
      {label = "block continuation"; needle = "Option<QemuLiveBlockIoServicerCheckpoint>";}
      {label = "node continuation"; needle = "pub struct QemuNodeContinuationCheckpoint";}
    ]
    ++ failuresFor "crates/crucible-qemu/src/node.rs" qemuNode [
      {label = "coordinated capture API"; needle = "pub fn capture_exact_snapshot";}
      {label = "node-addressed icount validation"; needle = "checkpoint.node_icounts.get(node)";}
      {label = "live boundary icount validation"; needle = "let observed_icount = self.current_icount()?";}
      {label = "host capture before VMState"; needle = ".checkpoint_host_io(checkpoint.id)";}
      {label = "opaque aggregate snapshot"; needle = "QemuVmSnapshot::from_live_capture";}
      {label = "forced crash gate"; needle = "force_crash_and_reap_for_gate";}
    ]
    ++ failuresFor "crates/crucible-qemu/src/node_factory.rs" qemuNodeFactory [
      {label = "host prevalidation"; needle = ".validate_host_io_checkpoint(checkpoint.id, host_io_checkpoint)";}
      {label = "authorized VMState restore"; needle = ".restore_checkpoint_vmstate_authorized(checkpoint)";}
      {label = "host continuation commit"; needle = ".restore_host_io_checkpoint(checkpoint.id, host_io_checkpoint)";}
      {label = "node continuation commit"; needle = "node.restore_node_continuation(continuation)";}
    ]
    ++ failuresFor "crates/crucible-qemu/examples/crucible-qemu-live-exact-snapshot.rs" qemuExactRunner [
      {label = "real exact runner"; needle = "run_qemu_live_exact_snapshot_gate";}
      {label = "pending block mode"; needle = "CRUCIBLE_EXACT_PENDING_BLOCK";}
      {label = "forced crash evidence"; needle = "old_process_force_crashed";}
      {label = "paired replay oracle"; needle = "replay_oracle_pair_match";}
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle/quantum_loop.rs" productionLoop [
      {label = "snapshot control boundary capture"; needle = "self.capture_exact_checkpoint_set(&configuration)?";}
      {label = "production paired capture"; needle = ".capture_exact_snapshot(&node, checkpoint)";}
      {label = "VMState artifact persistence"; needle = "PRODUCTION_VMSTATE_FILE_NAME";}
    ]
    ++ failuresFor "crates/crucible-api/src/vm_lifecycle/runtime.rs" productionRuntime [
      {label = "production exact relaunch"; needle = "launch_production_live_node_exact_snapshot";}
      {label = "artifact authentication"; needle = "failed authentication";}
      {label = "restored fingerprint check"; needle = "restored_fingerprint != expected_fingerprint";}
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/exact_snapshot_policy.rs" (builtins.readFile ../../crates/crucible-qemu/src/exact_snapshot_policy.rs) [
      {label = "public runtime loadvm minting"; needle = "pub const fn authorize_loadvm_runtime";}
      {label = "legacy fallback API"; needle = "Fallback";}
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU exact snapshot restore check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-exact-snapshot-restore";
      version = "0";
      src = crucibleSrc;
      buildDeps = [
        pkgs.coreutils
        pkgs.crucible-qemu-plugin
        pkgs.grep
        pkgs.qemu-crucible
        pkgs.rust
        pkgs.sed
      ];
      GUEST_KERNEL = builtins.toString pkgs.linux;
      DISKLESS_INITRD = "${idleInitramfs}/initrd.img";
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
            vmlinuz=$(ls "$GUEST_KERNEL"/boot/vmlinuz-* | head -1)
            test -n "$vmlinuz"
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/exact-snapshot-target" \
              --manifest-path crates/Cargo.toml -p crucible-qemu \
              qemu_node_captures_one_identity_bound_vmstate_and_host_io_pair \
              -- --test-threads=1
            cargo test --frozen --offline \
              --target-dir "$TMPDIR/exact-snapshot-target" \
              --manifest-path crates/Cargo.toml -p crucible-qemu \
              factory_restores_vmstate_before_exposing_exact_snapshot_control \
              -- --test-threads=1
            cargo build --frozen --offline \
              --target-dir "$TMPDIR/exact-snapshot-target" \
              --manifest-path crates/Cargo.toml -p crucible-qemu \
              --example crucible-qemu-live-exact-snapshot
            runner="$TMPDIR/exact-snapshot-target/debug/examples/crucible-qemu-live-exact-snapshot"

            diskless_report="$TMPDIR/exact-diskless.result"
            CRUCIBLE_EXACT_PENDING_BLOCK=0 \
            CRUCIBLE_EXACT_CAPTURE_CEILING=9000000 \
            CRUCIBLE_EXACT_SUFFIX_INCREMENT=3000000 \
              timeout -k 15 590 "$runner" \
                ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
                ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
                "$vmlinuz" "$GUEST_FIRMWARE" "$TMPDIR/exact-diskless" \
                "$DISKLESS_INITRD" > "$diskless_report"

            block_report="$TMPDIR/exact-block.result"
            CRUCIBLE_EXACT_PENDING_BLOCK=1 \
            CRUCIBLE_EXACT_CAPTURE_CEILING=80000000000 \
            CRUCIBLE_EXACT_SUFFIX_INCREMENT=3000000 \
              timeout -k 15 590 "$runner" \
                ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
                ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
                "$vmlinuz" "$GUEST_FIRMWARE" "$TMPDIR/exact-block" \
                "$BLOCK_INITRD" > "$block_report"

            cat "$diskless_report"
            cat "$block_report"
            for report in "$diskless_report" "$block_report"; do
              grep -Fxq PASS "$report"
              grep -Fxq 'gate=gate:qemu-exact-snapshot-restore' "$report"
              grep -Fxq 'vmstate_backend=real-qemu-qcow2' "$report"
              grep -Fxq 'host_io_backend=production-shared-memory-servicer' "$report"
              grep -Fxq 'old_process_force_crashed=true' "$report"
              grep -Fxq 'replay_oracle_pair_match=true' "$report"
              grep -Eq '^capture_icount=[1-9][0-9]*$' "$report"
              grep -Eq '^restored_icount=[1-9][0-9]*$' "$report"
              grep -Eq '^suffix_icount=[1-9][0-9]*$' "$report"
              grep -Eq '^capture_fingerprint=[0-9a-f]{64}$' "$report"
              grep -Eq '^suffix_fingerprint=[0-9a-f]{64}$' "$report"
            done
            grep -Fxq 'pending_block_io_captured=false' "$diskless_report"
            grep -Fxq 'pending_block_io_captured=true' "$block_report"

            mkdir -p "$out"
            {
              cat "$diskless_report"
              cat "$block_report"
              printf 'attr_path=%s\n' "$ATTR_PATH"
              printf 'task_ids=%s\n' "$TASK_IDS"
              printf 'scope=real-qemu-paired-save-force-crash-load-continue\n'
              printf 'proven=diskless-vmstate,pending-block-vmstate,host-continuation,node-continuation,fresh-process-restore,replay-oracle-suffix\n'
            } > "$out/result"
          '';
        }
      ];
    }
