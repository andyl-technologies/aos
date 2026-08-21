{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.blockCowOverlayPattern",
  taskIds ? ["T-IO-2" "T-IO-5" "T-PAT-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  patternDoc = builtins.readFile ../../docs/rfcs/0010-crucible/29-patterns-and-sketches.md;
  ioDoc = builtins.readFile ../../docs/rfcs/0010-crucible/15-io-subnodes.md;
  blockModule = builtins.readFile ../../crates/crucible-device/src/block.rs;
  overlay = builtins.readFile ../../crates/crucible-device/src/block/overlay.rs;
  device =
    builtins.readFile ../../crates/crucible-device/src/block/device.rs
    + builtins.readFile ../../crates/crucible-device/src/block/device/snapshot.rs;
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
        label = "completion names ordered dirty set";
        needle = "`BTreeSet`";
      }
      {
        label = "completion names dirty delta";
        needle = "`dirty_delta`";
      }
      {
        label = "completion names materialize";
        needle = "`BlockDevice::materialize`";
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
    ++ failuresFor "crates/crucible-device/src/block/overlay.rs" overlay [
      {
        label = "base image type";
        needle = "pub struct BaseImage";
      }
      {
        label = "base bytes private";
        needle = "bytes: Vec<u8>";
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
        label = "ordered overlay pages";
        needle = "pages: BTreeMap<u64, [u8; PAGE_SIZE]>";
      }
      {
        label = "ordered dirty set";
        needle = "dirty: BTreeSet<u64>";
      }
      {
        label = "overlay read wins";
        needle = "self.pages.get(&pb)";
      }
      {
        label = "base fallback read";
        needle = "let page = base.read_page(pb);";
      }
      {
        label = "copy-up from base";
        needle = "self.pages.entry(pb).or_insert_with(|| base.read_page(pb))";
      }
      {
        label = "dirty page tracking";
        needle = "self.dirty.insert(pb)";
      }
      {
        label = "delta captures dirty pages";
        needle = "pub fn dirty_delta(&self) -> OverlayDelta";
      }
      {
        label = "delta iterates dirty set";
        needle = "for &pb in &self.dirty";
      }
      {
        label = "materialize copies base first";
        needle = "let mut image = base.bytes().to_vec();";
      }
    ]
    ++ forbiddenFor "crates/crucible-device/src/block/overlay.rs" overlay [
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
    ++ failuresFor "crates/crucible-device/src/block/device.rs" device [
      {
        label = "block snapshot type";
        needle = "pub struct BlockSnapshot";
      }
      {
        label = "snapshot captures delta";
        needle = "overlay_delta: self.overlay.dirty_delta()";
      }
      {
        label = "snapshot captures full overlay pages";
        needle = "full_pages: self.overlay.all_pages().clone()";
      }
      {
        label = "snapshot captures dirty set";
        needle = "dirty: self.overlay.dirty_pages().clone()";
      }
      {
        label = "checkpoint clears dirty set";
        needle = "self.overlay.clear_dirty();";
      }
      {
        label = "restore stacks delta";
        needle = "overlay.apply_delta(&snapshot.overlay_delta)";
      }
      {
        label = "restore reinstates dirty set";
        needle = "overlay.set_dirty(snapshot.dirty.clone())";
      }
      {
        label = "materialize delegates overlay";
        needle = "self.overlay.materialize(&self.base)";
      }
    ]
    ++ failuresFor "crates/crucible-device/src/block.rs" blockModule [
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
        label = "delta page hash test";
        needle = "delta_pages_are_blake3_keyed";
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
    pkgs.mkDerivation {
      pname = "crucible-phase3-block-cow-overlay-pattern";
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
          name = "run-block-cow-overlay-tests";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-block-cow-overlay-pattern-target" \
              --manifest-path crates/Cargo.toml \
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
            overlay_pages=BTreeMap-4KiB
            dirty_pages=BTreeSet-deterministic-delta
            materialize=copy-base-then-overlay
            RESULT
          '';
        }
      ];
    }
