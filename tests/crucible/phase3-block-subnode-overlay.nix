{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.blockSubnodeOverlay",
  taskIds ? ["T-IO-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  blockSubnode = builtins.readFile ../../crates/crucible/src/block_subnode.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/block_subnode_overlay.rs;
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
        label = "T-IO-2 checked off";
        needle = "- [x] **T-IO-2**";
      }
      {
        label = "T-IO-2 completion note";
        needle = "Completed by `checks.crucible.phase3.blockSubnodeOverlay`";
      }
      {
        label = "read-only content-addressed base note";
        needle = "immutable content-addressed base image";
      }
      {
        label = "4 KiB CoW page note";
        needle = "4 KiB copy-on-write overlay pages";
      }
      {
        label = "dirty delta note";
        needle = "dirty pages since the last checkpoint boundary";
      }
      {
        label = "base never mutated note";
        needle = "base image is never mutated";
      }
    ]
    ++ failuresFor "crates/crucible/src/block_subnode.rs" blockSubnode [
      {
        label = "page size constant";
        needle = "pub const BLOCK_OVERLAY_PAGE_SIZE: usize = 4096";
      }
      {
        label = "content-addressed base";
        needle = "pub struct BlockBaseImage";
      }
      {
        label = "content ref";
        needle = "ContentAddressedBlobRef";
      }
      {
        label = "content hash check";
        needle = "ContentHash::from_bytes";
      }
      {
        label = "overlay model";
        needle = "pub struct BlockSubNodeOverlay";
      }
      {
        label = "ordered overlay pages";
        needle = "BTreeMap";
      }
      {
        label = "ordered dirty pages";
        needle = "BTreeSet";
      }
      {
        label = "read operation";
        needle = "pub fn read";
      }
      {
        label = "write operation";
        needle = "pub fn write";
      }
      {
        label = "copy-up from base";
        needle = "copy_page";
      }
      {
        label = "flush operation";
        needle = "pub fn flush";
      }
      {
        label = "get length operation";
        needle = "pub const fn get_length";
      }
      {
        label = "dirty delta capture";
        needle = "capture_dirty_delta";
      }
      {
        label = "range bounds error";
        needle = "RangeOutOfBounds";
      }
      {
        label = "delta content hash";
        needle = "block_overlay_delta_bytes";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/block_subnode.rs" blockSubnode [
      {
        label = "filesystem dependency";
        needle = "std::fs";
      }
      {
        label = "file handle dependency";
        needle = "File";
      }
      {
        label = "host path dependency";
        needle = "PathBuf";
      }
      {
        label = "filesystem metadata dependency";
        needle = "Metadata";
      }
      {
        label = "unordered overlay map";
        needle = "HashMap";
      }
      {
        label = "unordered dirty set";
        needle = "HashSet";
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
        label = "module exported";
        needle = "pub mod block_subnode";
      }
      {
        label = "overlay exported";
        needle = "BlockSubNodeOverlay";
      }
      {
        label = "base exported";
        needle = "BlockBaseImage";
      }
    ]
    ++ failuresFor "crates/crucible/tests/block_subnode_overlay.rs" focusedTest [
      {
        label = "focused overlay test";
        needle = "deterministic block sub-node base+overlay behavior";
      }
      {
        label = "overlay read priority test";
        needle = "reads_resolve_overlay_pages_before_immutable_base";
      }
      {
        label = "copy-up dirty test";
        needle = "partial_write_faults_in_a_whole_page_and_dirties_only_that_page";
      }
      {
        label = "sorted dirty delta test";
        needle = "dirty_delta_is_sorted_unique_and_cleared_after_capture";
      }
      {
        label = "bounds test";
        needle = "ranges_past_the_base_length_fail_without_extending_the_device";
      }
      {
        label = "final page zero fill test";
        needle = "final_partial_page_delta_is_zero_filled_beyond_device_length";
      }
      {
        label = "flush and length test";
        needle = "flush_is_a_noop_success_and_get_length_reports_base_size";
      }
      {
        label = "content ref mismatch test";
        needle = "base_image_constructor_rejects_mismatched_content_address";
      }
      {
        label = "overflow test";
        needle = "overflowing_ranges_fail_before_any_overlay_mutation";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/block_subnode_overlay.rs" focusedTest [
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
        label = "phase3 exposes block overlay check";
        needle = "blockSubnodeOverlay = import ./phase3-block-subnode-overlay.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 block sub-node overlay check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-block-subnode-overlay";
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
          name = "run-block-subnode-overlay";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-block-subnode-overlay-target" \
              -p crucible \
              --test block_subnode_overlay \
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
            component=crucible-block-subnode-overlay
            gate=gate:content-address,gate:abi-conformance
            read_only_content_addressed_base=true
            cow_4k_overlay_pages=true
            dirty_page_delta_tracking=true
            RESULT
          '';
        }
      ];
    }
