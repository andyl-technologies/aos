{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.shmemSnapshotRestore",
  taskIds ? ["T-SHM-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  snapshotTest = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible-shmem/tests/snapshot_restore.rs;
  };
  shmemSpec = builtins.readFile ../../docs/rfcs/0010-crucible/13-shmem-abi.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "quiescent snapshot API";
        needle = "pub fn snapshot(&self, entries: &[FrameEntry]) -> Result<SpscRingSnapshot, SpscRingError>";
      }
      {
        label = "snapshot canonicalization helper";
        needle = "fn canonicalized_for_snapshot(&self) -> Result<Self, SpscRingError>";
      }
      {
        label = "snapshot padding canonicalization";
        needle = "canonical._pad = [0; 1];";
      }
      {
        label = "unused payload canonicalization";
        needle = "canonical.data[len..].fill(0);";
      }
      {
        label = "canonical byte serialization";
        needle = "pub fn canonical_bytes(&self) -> Result<Vec<u8>, SpscRingError>";
      }
      {
        label = "canonical frame-count prefix";
        needle = "bytes.extend_from_slice(&frame_count.to_le_bytes());";
      }
      {
        label = "canonical delivery icount field";
        needle = "bytes.extend_from_slice(&canonical.delivery_icount.to_le_bytes());";
      }
      {
        label = "canonical delivery state field";
        needle = "bytes.push(delivery_state as u8);";
      }
      {
        label = "canonical valid payload only";
        needle = "bytes.extend_from_slice(&canonical.data[..payload_len]);";
      }
      {
        label = "quiescent restore API";
        needle = "pub fn restore(";
      }
      {
        label = "restore read-index normalization";
        needle = "self.read_idx.store(0, Ordering::Release);";
      }
      {
        label = "restore write-index normalization";
        needle = ".store(snapshot.frames.len() as u64, Ordering::Release);";
      }
      {
        label = "corrupt frame length error";
        needle = "InvalidFrameLength";
      }
      {
        label = "oversized snapshot error";
        needle = "SnapshotTooLarge";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/snapshot_restore.rs" snapshotTest [
      {
        label = "FIFO snapshot canonicalization test";
        needle = "snapshot_captures_fifo_after_wraparound_and_canonicalizes_entries";
      }
      {
        label = "restore normalization test";
        needle = "restore_normalizes_indices_and_replays_snapshot_frames";
      }
      {
        label = "oversized restore rejection test";
        needle = "restore_rejects_snapshot_larger_than_target_capacity";
      }
      {
        label = "corrupt ring frame rejection test";
        needle = "snapshot_rejects_corrupt_frame_length_before_serializing";
      }
      {
        label = "corrupt snapshot frame rejection test";
        needle = "canonical_decoder_rejects_corrupt_snapshot_frame_length";
      }
      {
        label = "unused payload negative control";
        needle = "frame_with_unused_tail";
      }
      {
        label = "compact snapshot amplification control";
        needle = "canonical_decoder_keeps_minimal_frames_compact";
      }
    ]
    ++ forbiddenFor "crates/crucible-shmem/tests/snapshot_restore.rs" snapshotTest [
      {
        label = "ignored snapshot/restore test";
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
        label = "phase2 exposes shmem snapshot/restore check";
        needle = "shmemSnapshotRestore = import ./phase2-shmem-snapshot-restore.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 shmem snapshot/restore check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-shmem-snapshot-restore";
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
          name = "run-shmem-snapshot-restore";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-shmem-snapshot-restore-target" \
              -p crucible-shmem \
              --test snapshot_restore \
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
            gate=gate:abi-conformance
            gate=gate:content-address
            gate=gate:replay-oracle
            rust_tests=crucible-shmem::snapshot_restore
            snapshot_fifo=true
            restore_normalizes_indices=true
            canonical_bytes=padding_independent
            corrupt_frame_lengths=rejected
            RESULT
          '';
        }
      ];
    }
