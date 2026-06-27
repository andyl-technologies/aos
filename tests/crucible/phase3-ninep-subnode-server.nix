{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.ninePSubnodeServer",
  taskIds ? ["T-IO-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  ninepSubnode = builtins.readFile ../../crates/crucible/src/ninep_subnode.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/ninep_subnode_server.rs;
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
        label = "T-IO-6 checked off";
        needle = "- [x] **T-IO-6**";
      }
      {
        label = "T-IO-6 completion note";
        needle = "Completed by `checks.crucible.phase3.ninePSubnodeServer`";
      }
      {
        label = "path hash note";
        needle = "QID `path` values derived from a stable hash of the path within the served";
      }
      {
        label = "fixed qid version note";
        needle = "fixed `NINEP_FIXED_QID_VERSION`";
      }
      {
        label = "host metadata exclusion note";
        needle = "no host inode, filesystem metadata, timestamp, uid/gid, or directory iteration input";
      }
      {
        label = "sorted readdir note";
        needle = "`readdir` sorts child names lexicographically and assigns offsets after sorting";
      }
      {
        label = "fixed attrs note";
        needle = "fixed epoch/root uid/root gid/block size, no advertised write permission bits, and 512-byte size-derived block counts";
      }
      {
        label = "statfs fsid note";
        needle = "`statfs.fsid` derives from served-tree content and ignores negotiation msize";
      }
      {
        label = "version negotiation note";
        needle = "accepts only `9P2000.L` and deterministically";
      }
      {
        label = "msize formula note";
        needle = "`msize = min(client_msize, server_maximum_msize)`";
      }
    ]
    ++ failuresFor "crates/crucible/src/ninep_subnode.rs" ninepSubnode [
      {
        label = "module docs";
        needle = "Deterministic read-only 9P2000.L served-tree model";
      }
      {
        label = "fixed protocol constant";
        needle = "pub const NINEP_PROTOCOL_VERSION: &str = \"9P2000.L\"";
      }
      {
        label = "fixed qid version";
        needle = "pub const NINEP_FIXED_QID_VERSION: u32 = 1";
      }
      {
        label = "fixed epoch";
        needle = "pub const NINEP_FIXED_EPOCH_SECONDS";
      }
      {
        label = "fixed uid";
        needle = "pub const NINEP_FIXED_UID";
      }
      {
        label = "fixed gid";
        needle = "pub const NINEP_FIXED_GID";
      }
      {
        label = "fixed block size";
        needle = "pub const NINEP_FIXED_BLOCK_SIZE";
      }
      {
        label = "fixed 512-byte blocks";
        needle = "pub const NINEP_BLOCK_COUNT_UNIT: u64 = 512";
      }
      {
        label = "served tree type";
        needle = "pub struct NinePServedTree";
      }
      {
        label = "served entry type";
        needle = "pub struct NinePServedEntry";
      }
      {
        label = "qid type";
        needle = "pub struct NinePQid";
      }
      {
        label = "directory entry type";
        needle = "pub struct NinePDirectoryEntry";
      }
      {
        label = "attributes type";
        needle = "pub struct NinePAttributes";
      }
      {
        label = "statfs type";
        needle = "pub struct NinePStatFs";
      }
      {
        label = "version negotiation type";
        needle = "pub struct NinePVersionNegotiation";
      }
      {
        label = "qid path domain";
        needle = "NINEP_QID_PATH_DOMAIN";
      }
      {
        label = "stable qid path hash";
        needle = "ContentHash::from_canonical_material(NINEP_QID_PATH_DOMAIN, path)";
      }
      {
        label = "qid fixed version";
        needle = "version: NINEP_FIXED_QID_VERSION";
      }
      {
        label = "sorted readdir";
        needle = "children.sort_by(|left, right| left.0.cmp(&right.0))";
      }
      {
        label = "offset after sort";
        needle = ".checked_add(1)";
      }
      {
        label = "getattr";
        needle = "pub fn getattr";
      }
      {
        label = "statfs";
        needle = "pub fn statfs";
      }
      {
        label = "block count";
        needle = "fn block_count";
      }
      {
        label = "block count unit";
        needle = "NINEP_BLOCK_COUNT_UNIT";
      }
      {
        label = "read-only permission sanitizer";
        needle = "fn read_only_permissions";
      }
      {
        label = "write bit stripping";
        needle = "permissions & 0o555";
      }
      {
        label = "version negotiation";
        needle = "pub fn negotiate_version";
      }
      {
        label = "fixed version check";
        needle = "client_version != NINEP_PROTOCOL_VERSION";
      }
      {
        label = "deterministic msize";
        needle = "msize: client_msize.min(self.maximum_msize)";
      }
      {
        label = "tree content hash";
        needle = "pub fn content_hash";
      }
      {
        label = "path validation";
        needle = "normalize_served_path";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/ninep_subnode.rs" ninepSubnode [
      {
        label = "host filesystem API";
        needle = "std::fs";
      }
      {
        label = "host path dependency";
        needle = "PathBuf";
      }
      {
        label = "host metadata dependency";
        needle = "Metadata";
      }
      {
        label = "wall-clock API";
        needle = "SystemTime";
      }
      {
        label = "host epoch API";
        needle = "UNIX_EPOCH";
      }
      {
        label = "environment dependency";
        needle = "std::env";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "randomized hasher";
        needle = "RandomState";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "module exported";
        needle = "pub mod ninep_subnode";
      }
      {
        label = "served tree exported";
        needle = "NinePServedTree";
      }
      {
        label = "qid exported";
        needle = "NinePQid";
      }
      {
        label = "version constant exported";
        needle = "NINEP_PROTOCOL_VERSION";
      }
      {
        label = "block count unit exported";
        needle = "NINEP_BLOCK_COUNT_UNIT";
      }
    ]
    ++ failuresFor "crates/crucible/tests/ninep_subnode_server.rs" focusedTest [
      {
        label = "focused 9p test";
        needle = "deterministic read-only 9P2000.L served-tree behavior";
      }
      {
        label = "qid test";
        needle = "qids_are_path_hashed_with_fixed_version_and_kind_not_host_inode_inputs";
      }
      {
        label = "readdir test";
        needle = "readdir_is_lexicographic_and_offsets_are_assigned_after_sort";
      }
      {
        label = "getattr statfs test";
        needle = "getattr_and_statfs_are_fixed_or_content_derived";
      }
      {
        label = "read-only permissions test";
        needle = "custom_permissions_never_advertise_write_bits";
      }
      {
        label = "512-byte block count test";
        needle = "getattr_blocks_use_fixed_512_byte_units_not_preferred_block_size";
      }
      {
        label = "version negotiation test";
        needle = "version_negotiation_uses_fixed_protocol_and_deterministic_msize";
      }
      {
        label = "authoring order test";
        needle = "served_tree_hash_and_readdir_are_independent_of_authoring_order";
      }
      {
        label = "fsid ignores msize test";
        needle = "statfs_fsid_and_tree_content_hash_ignore_negotiation_msize";
      }
      {
        label = "validation test";
        needle = "validation_rejects_nondeterministic_or_non_tree_paths";
      }
      {
        label = "typed lookup errors test";
        needle = "lookup_and_readdir_errors_are_typed";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/ninep_subnode_server.rs" focusedTest [
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
        label = "phase3 exposes 9p server check";
        needle = "ninePSubnodeServer = import ./phase3-ninep-subnode-server.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 9p subnode server check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-ninep-subnode-server";
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
          name = "run-ninep-subnode-server";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-ninep-subnode-server-target" \
              -p crucible \
              --test ninep_subnode_server \
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
            component=crucible-ninep-subnode-server
            gate=gate:any-guest,gate:adversarial-determinism,gate:abi-conformance
            qid=path-hash-fixed-version
            readdir=lexicographic-offsets-after-sort
            attrs=fixed-or-content-derived
            version=9P2000.L
            RESULT
          '';
        }
      ];
    }
