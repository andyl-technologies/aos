{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.blockCowOverlayPattern",
  taskIds ? ["T-IO-2" "T-IO-5" "T-PAT-7"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  patternDoc = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
  ioDoc = builtins.readFile ../../docs/rfcs/0010-crucible/15-io-subnodes.md;
  blockModule =
    import ./_rust-module-source.nix {
      inherit lib;
      entry = ../../crates/crucible/crucible-device/src/block.rs;
      siblingTests = true;
    }
    + builtins.readFile ../../crates/crucible/crucible-device/src/block_overlay_codec_test.rs
    + builtins.readFile ../../crates/crucible/crucible-device/src/block_snapshot_array_test.rs;
  overlay = builtins.readFile ../../crates/crucible/crucible-device/src/block/overlay.rs;
  overlayImage = builtins.readFile ../../crates/crucible/crucible-device/src/block/overlay_image.rs;
  device =
    import ./_rust-module-source.nix {
      inherit lib;
      entry = ../../crates/crucible/crucible-device/src/block/device.rs;
    }
    + builtins.readFile ../../crates/crucible/crucible-device/src/block/device/snapshot.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/29-patterns-and-sketches.md" patternDoc [
      {
        label = "T-PAT-7 completion note";
        needle = "Completed by `checks.crucible.phase3.blockCowOverlayPattern`";
      }
      {
        label = "completion names BaseImage";
        needle = "`BaseImage`";
      }
      {
        label = "completion names CowOverlay";
        needle = "`CowOverlay`";
      }
      {
        label = "completion names ordered maps";
        needle = "`BTreeMap`";
      }
      {
        label = "completion names dirty page bitmaps";
        needle = "`ChunkPageBits`";
      }
      {
        label = "completion names page store";
        needle = "`BlockPageStore`";
      }
      {
        label = "completion names overlay freeze";
        needle = "`CowOverlay::freeze`";
      }
      {
        label = "completion names chunked overlay image";
        needle = "`BlockOverlayImage`";
      }
      {
        label = "completion names materialize";
        needle = "`BlockDevice::materialize_to`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/15-io-subnodes.md" ioDoc [
      {
        label = "T-IO-2 completion note";
        needle = "Completed by `checks.crucible.phase3.blockSubnodeOverlay`";
      }
      {
        label = "T-IO-5 completion note";
        needle = "Completed by `checks.crucible.phase3.blockSnapshotRestore`";
      }
      {
        label = "read-only base requirement";
        needle = "read-only, content-addressed base image";
      }
      {
        label = "4 KiB CoW overlay requirement";
        needle = "in-memory 4 KiB CoW page overlay";
      }
      {
        label = "dirty-page delta requirement";
        needle = "Dirty tracking records only the dirty pages since the last checkpoint boundary";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-device/src/block/overlay.rs" overlay [
      {
        label = "base image type";
        needle = "pub struct BaseImage";
      }
      {
        label = "base bytes private and shared";
        needle = "bytes: Arc<[u8]>";
      }
      {
        label = "base content hash";
        needle = "hash: [u8; 32]";
      }
      {
        label = "read-only base bytes accessor";
        needle = "pub fn bytes(&self) -> &[u8]";
      }
      {
        label = "CoW overlay type";
        needle = "pub struct CowOverlay";
      }
      {
        label = "ordered overlay chunk table";
        needle = "chunks: BTreeMap<u64, Arc<OverlayChunk>>";
      }
      {
        label = "ordered dirty page bitmaps";
        needle = "dirty: BTreeMap<u64, ChunkPageBits>";
      }
      {
        label = "overlay pages held in a page store";
        needle = "store: BlockPageStore";
      }
      {
        label = "overlay read wins";
        needle = "match self.stored_page(pb) {";
      }
      {
        label = "base fallback read";
        needle = "None => target.copy_from_slice(&base.read_page(pb)[page_off..page_off + take])";
      }
      {
        label = "copy-up from base";
        needle = "let mut copy = base.read_page(page_base);";
      }
      {
        label = "shared page copied before patch";
        needle = ".patch_if_unique(page_off, bytes)";
      }
      {
        label = "dirty page tracking";
        needle = "self.dirty.entry(chunk_index).or_default().insert(slot);";
      }
      {
        label = "chunk identity is the BLAKE3 key of its bytes";
        needle = "let identity = nonzero.then(|| *hasher.finalize().as_bytes());";
      }
      {
        label = "freeze captures chunks with dirty pages";
        needle = "BlockOverlayImage::from_live(length, &self.chunks, &self.dirty)";
      }
      {
        label = "dirty pages iterate in ascending order";
        needle = ".flat_map(|(chunk, bits)| bits.iter().map(move |slot| page_base_at(*chunk, slot)))";
      }
      {
        label = "materialize streams base under overlay pages";
        needle = "None => page[..span].copy_from_slice(&base.read_page(page_base)[..span]),";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-device/src/block/overlay.rs" overlay [
      {
        label = "unordered overlay map";
        needle = "HashMap";
      }
      {
        label = "unordered dirty set";
        needle = "HashSet";
      }
      {
        label = "mutable base bytes accessor";
        needle = "bytes_mut";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-device/src/block/overlay_image.rs" overlayImage [
      {
        label = "chunked overlay image type";
        needle = "pub struct BlockOverlayImage";
      }
      {
        label = "ordered image chunks";
        needle = "chunks: BTreeMap<u64, ImageChunk>";
      }
      {
        label = "image chunk records carry dirty pages";
        needle = "pub dirty: ChunkPageBits,";
      }
      {
        label = "decoded dirty pages stay within present pages";
        needle = "!record.dirty.is_subset(&record.present)";
      }
      {
        label = "stored chunks authenticated against identity";
        needle = "if *blake3::hash(bytes).as_bytes() != identity {";
      }
      {
        label = "restore reinstates dirty pages";
        needle = "dirty.insert(*index, chunk.dirty);";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-device/src/block/overlay_image.rs" overlayImage [
      {
        label = "unordered image chunk map";
        needle = "HashMap";
      }
      {
        label = "unordered image page set";
        needle = "HashSet";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-device/src/block/device.rs" device [
      {
        label = "block snapshot type";
        needle = "pub struct BlockSnapshot";
      }
      {
        label = "snapshot freezes overlay chunks";
        needle = "overlay: self.overlay.freeze(self.base.len())";
      }
      {
        label = "snapshot carries chunked overlay image";
        needle = "pub overlay: BlockOverlayImage";
      }
      {
        label = "snapshot chunk records carry present and dirty pages";
        needle = "struct OverlayChunkWire(u64, Option<[u8; 32]>, [u64; 16], [u64; 16]);";
      }
      {
        label = "checkpoint clears dirty set";
        needle = "self.overlay.clear_dirty();";
      }
      {
        label = "restore rebuilds overlay from authenticated chunks";
        needle = "let overlay = snapshot.overlay.materialize_into(store)?;";
      }
      {
        label = "restore validation authenticates chunks";
        needle = "snapshot.overlay.verify()";
      }
      {
        label = "materialize delegates overlay";
        needle = "self.overlay.materialize_to(&self.base, output)";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-device/src/block.rs" blockModule [
      {
        label = "fall-through read test";
        needle = "read_falls_through_to_base_when_overlay_empty";
      }
      {
        label = "copy-up read test";
        needle = "write_copies_up_and_read_sees_overlay_over_base";
      }
      {
        label = "base immutability test";
        needle = "base_bytes_never_change_under_writes";
      }
      {
        label = "dirty tracking test";
        needle = "dirty_set_tracks_written_pages_and_clears_at_boundary";
      }
      {
        label = "materialize immutability test";
        needle = "materialize_applies_overlay_over_base_without_mutating_base";
      }
      {
        label = "snapshot excludes base test";
        needle = "snapshot_excludes_base_and_restore_round_trips";
      }
      {
        label = "dirty-set restore regression";
        needle = "regression_restore_preserves_mid_epoch_dirty_set";
      }
      {
        label = "overlay chunk hash test";
        needle = "overlay_chunks_are_blake3_keyed";
      }
      {
        label = "disk and heap overlay equivalence test";
        needle = "disk_overlay_matches_heap_overlay_and_reference_across_writes_forks_and_restores";
      }
      {
        label = "stored chunk authentication test";
        needle = "restore_authenticates_every_stored_chunk";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes block CoW overlay pattern check";
        needle = "blockCowOverlayPattern = import ./phase3-block-cow-overlay-pattern.nix";
      }
      {
        label = "gate task IDs include pattern and IO owners";
        needle = "taskIds = [\"T-IO-2\" \"T-IO-5\" \"T-PAT-7\"]";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 block CoW overlay pattern check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase3-block-cow-overlay-pattern";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
      ];

      phases = [
        {
          name = "run-block-cow-overlay-tests";
          script = ''
            set -eu
            crucible-cargo test \
              -p crucible-device \
              block::tests \
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
            component=crucible-block-cow-overlay
            base_image=read-only-content-addressed
            overlay_pages=BTreeMap-4MiB-chunks-of-4KiB-pages
            dirty_pages=BTreeMap-chunk-bitmaps-deterministic
            materialize=stream-base-under-overlay
            RESULT
          '';
        }
      ];
    }
