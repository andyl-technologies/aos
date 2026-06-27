{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.blockSnapshotRestore",
  taskIds ? ["T-IO-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  blockSubnode = builtins.readFile ../../crates/crucible/src/block_subnode.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/block_subnode_snapshot.rs;
  ioDoc = builtins.readFile ../../docs/rfcs/0010-crucible/15-io-subnodes.md;
  defaultChecks = builtins.readFile ./default.nix;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/15-io-subnodes.md" ioDoc [
      {
        label = "T-IO-5 checked off";
        needle = "- [x] **T-IO-5**";
      }
      {
        label = "T-IO-5 completion note";
        needle = "Completed by `checks.crucible.phase3.blockSnapshotRestore`";
      }
      {
        label = "delta over parent note";
        needle = "captures a `BlockOverlayDelta` of dirty pages over the parent overlay";
      }
      {
        label = "RNG position note";
        needle = "`DeviceRngState` stream positions";
      }
      {
        label = "base exclusion note";
        needle = "never embeds base image bytes";
      }
      {
        label = "restore validation note";
        needle = "validates the base reference, length, page alignment, strict page order, page size, and bounds";
      }
      {
        label = "restore in-flight order note";
        needle = "in-flight responses normalized to deterministic order";
      }
      {
        label = "materialize note";
        needle = "`materialize_image` writes base bytes and then every live overlay page";
      }
    ]
    ++ failuresFor "crates/crucible/src/block_subnode.rs" blockSubnode [
      {
        label = "snapshot type";
        needle = "pub struct BlockSubNodeSnapshot";
      }
      {
        label = "restored runtime state type";
        needle = "pub struct RestoredBlockSubNodeState";
      }
      {
        label = "snapshot RNG field";
        needle = "pub device_rng: DeviceRngState";
      }
      {
        label = "snapshot in-flight field";
        needle = "pub in_flight: Vec<IoSubNodeCompletion>";
      }
      {
        label = "snapshot clock field";
        needle = "pub clock_icount: Icount";
      }
      {
        label = "snapshot length field";
        needle = "pub length: u64";
      }
      {
        label = "snapshot content hash";
        needle = "pub fn content_hash";
      }
      {
        label = "capture snapshot";
        needle = "pub fn capture_snapshot";
      }
      {
        label = "dirty delta capture";
        needle = "delta: self.capture_dirty_delta()";
      }
      {
        label = "in-flight sorting";
        needle = "in_flight.sort_by(block_inflight_response_order)";
      }
      {
        label = "restore snapshot";
        needle = "pub fn restore_snapshot";
      }
      {
        label = "restore in-flight sorting";
        needle = "restored_in_flight.sort_by(block_inflight_response_order)";
      }
      {
        label = "apply delta";
        needle = "pub fn apply_delta";
      }
      {
        label = "base validation";
        needle = "BlockSnapshotError::BaseImageMismatch";
      }
      {
        label = "length validation";
        needle = "BlockSnapshotError::LengthMismatch";
      }
      {
        label = "page alignment validation";
        needle = "DeltaPageMisaligned";
      }
      {
        label = "page order validation";
        needle = "DeltaPageOutOfOrder";
      }
      {
        label = "page size validation";
        needle = "InvalidDeltaPageSize";
      }
      {
        label = "page bounds validation";
        needle = "DeltaPageOutOfBounds";
      }
      {
        label = "two-phase delta restore staging";
        needle = "let mut restored_pages = Vec::with_capacity(delta.pages.len())";
      }
      {
        label = "delta mutation after validation";
        needle = "for (page_base, page_bytes) in restored_pages";
      }
      {
        label = "restore clears dirty set";
        needle = "self.dirty.clear()";
      }
      {
        label = "materialize image";
        needle = "pub fn materialize_image";
      }
      {
        label = "base clone for image";
        needle = "self.base.bytes().to_vec()";
      }
      {
        label = "overlay patching";
        needle = "apply_page_to_image";
      }
      {
        label = "materialized hash";
        needle = "pub fn materialized_content_hash";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/block_subnode.rs" blockSubnode [
      {
        label = "host path dependency";
        needle = "PathBuf";
      }
      {
        label = "filesystem materialization";
        needle = "std::fs";
      }
      {
        label = "wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "instant dependency";
        needle = "std::time::Instant";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "snapshot exported";
        needle = "BlockSubNodeSnapshot";
      }
      {
        label = "snapshot error exported";
        needle = "BlockSnapshotError";
      }
      {
        label = "restored runtime state exported";
        needle = "RestoredBlockSubNodeState";
      }
    ]
    ++ failuresFor "crates/crucible/tests/block_subnode_snapshot.rs" focusedTest [
      {
        label = "focused snapshot test";
        needle = "block snapshot/restore and materialization behavior";
      }
      {
        label = "snapshot captures state test";
        needle = "snapshot_captures_dirty_delta_rng_inflight_clock_and_length_without_base_bytes";
      }
      {
        label = "restore stacks delta test";
        needle = "restore_stacks_delta_over_parent_overlay_and_returns_runtime_state";
      }
      {
        label = "materialize image test";
        needle = "materialize_image_writes_base_then_live_overlay_pages_without_mutating_base";
      }
      {
        label = "snapshot hash test";
        needle = "snapshot_content_hash_tracks_delta_rng_inflight_clock_and_length";
      }
      {
        label = "forged snapshot rejection test";
        needle = "restore_rejects_forged_base_length_and_delta_pages";
      }
      {
        label = "no partial restore mutation test";
        needle = "restore_rejects_invalid_delta_without_partial_overlay_mutation";
      }
      {
        label = "delta stacking test";
        needle = "apply_delta_stacks_without_marking_restored_pages_dirty";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/block_subnode_snapshot.rs" focusedTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending placeholder";
        needle = "todo!";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase3 exposes block snapshot check";
        needle = "blockSnapshotRestore = import ./phase3-block-snapshot-restore.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 block snapshot restore check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-block-snapshot-restore";
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
          name = "run-block-snapshot-restore";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-block-snapshot-restore-target" \
              -p crucible \
              --test block_subnode_snapshot \
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
            component=crucible-block-snapshot-restore
            gate=gate:replay-oracle,gate:content-address,gate:any-guest
            snapshot=delta-plus-rng-plus-inflight
            restore=stack-delta-over-parent
            materialize=base-plus-live-overlay-pages
            RESULT
          '';
        }
      ];
    }
