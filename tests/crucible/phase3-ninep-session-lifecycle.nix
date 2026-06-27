{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase3.ninePSessionLifecycle",
  taskIds ? ["T-IO-7"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  ninepSubnode = builtins.readFile ../../crates/crucible/src/ninep_subnode.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  focusedTest = builtins.readFile ../../crates/crucible/tests/ninep_session_lifecycle.rs;
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
        label = "T-IO-7 checked off";
        needle = "- [x] **T-IO-7**";
      }
      {
        label = "T-IO-7 completion note";
        needle = "Completed by `checks.crucible.phase3.ninePSessionLifecycle`";
      }
      {
        label = "request set note";
        needle = "`NinePSession` handles the high-level Tversion/Tattach/Twalk/Tlopen/Tread/Treaddir/Tgetattr/Treadlink/Tclunk/Tstatfs/Tflush/Txattrwalk request set";
      }
      {
        label = "msize note";
        needle = "enforces negotiated `msize` before mutating fid state";
      }
      {
        label = "modeled request size note";
        needle = "derives modeled request sizes including minimum 9P2000.L fixed fields before the negotiated `msize` guard";
      }
      {
        label = "read payload limit note";
        needle = "clamps `Tread` payloads and `Treaddir` byte-budgeted entries to the negotiated message budget";
      }
      {
        label = "mutating EROFS note";
        needle = "rejects every `NinePMutatingMessage` with `NINEP_EROFS`";
      }
      {
        label = "unknown ENOSYS note";
        needle = "maps unknown requests to `NINEP_ENOSYS`";
      }
      {
        label = "malformed error note";
        needle = "maps malformed request bodies to `NINEP_EINVAL` or `NINEP_EIO`";
      }
      {
        label = "fid snapshot note";
        needle = "`NinePSessionSnapshot` persists negotiated msize plus fid snapshots";
      }
      {
        label = "version reset note";
        needle = "`Tversion` deterministically resets the fid table";
      }
      {
        label = "xattr fid note";
        needle = "keeps xattr fids as distinct empty file-like targets";
      }
      {
        label = "cache reconstruction note";
        needle = "restore reconstructs file handles and directory caches from the read-only tree";
      }
    ]
    ++ failuresFor "crates/crucible/src/ninep_subnode.rs" ninepSubnode [
      {
        label = "session type";
        needle = "pub struct NinePSession";
      }
      {
        label = "request type";
        needle = "pub struct NinePRequest";
      }
      {
        label = "request kind";
        needle = "pub enum NinePRequestKind";
      }
      {
        label = "response type";
        needle = "pub struct NinePResponse";
      }
      {
        label = "response kind";
        needle = "pub enum NinePResponseKind";
      }
      {
        label = "mutating enum";
        needle = "pub enum NinePMutatingMessage";
      }
      {
        label = "session snapshot";
        needle = "pub struct NinePSessionSnapshot";
      }
      {
        label = "fid snapshot";
        needle = "pub struct NinePFidSnapshot";
      }
      {
        label = "fid table";
        needle = "fids: BTreeMap<u32, NinePFidState>";
      }
      {
        label = "fid target enum";
        needle = "enum NinePFidTarget";
      }
      {
        label = "version request";
        needle = "NinePRequestKind::Version";
      }
      {
        label = "attach request";
        needle = "NinePRequestKind::Attach";
      }
      {
        label = "walk request";
        needle = "NinePRequestKind::Walk";
      }
      {
        label = "lopen request";
        needle = "NinePRequestKind::Lopen";
      }
      {
        label = "read request";
        needle = "NinePRequestKind::Read";
      }
      {
        label = "readdir request";
        needle = "NinePRequestKind::Readdir";
      }
      {
        label = "getattr request";
        needle = "NinePRequestKind::GetAttr";
      }
      {
        label = "readlink request";
        needle = "NinePRequestKind::ReadLink";
      }
      {
        label = "clunk request";
        needle = "NinePRequestKind::Clunk";
      }
      {
        label = "statfs request";
        needle = "NinePRequestKind::StatFs";
      }
      {
        label = "flush request";
        needle = "NinePRequestKind::Flush";
      }
      {
        label = "xattrwalk request";
        needle = "NinePRequestKind::XattrWalk";
      }
      {
        label = "msize check";
        needle = "if request.encoded_size > self.negotiated_msize";
      }
      {
        label = "modeled request size";
        needle = "fn encoded_request_size";
      }
      {
        label = "attach fixed fields";
        needle = "NinePRequestKind::Attach { .. } => NINEP_HEADER_SIZE";
      }
      {
        label = "getattr fixed mask";
        needle = "NinePRequestKind::GetAttr { .. } => NINEP_HEADER_SIZE";
      }
      {
        label = "flush oldtag field";
        needle = "NinePRequestKind::Flush => NINEP_HEADER_SIZE.saturating_add(NINEP_U16_SIZE)";
      }
      {
        label = "msize error";
        needle = "return ninep_error(request.tag, NINEP_EINVAL)";
      }
      {
        label = "read payload limit";
        needle = "count.min(self.read_payload_limit())";
      }
      {
        label = "readdir byte budget";
        needle = "encoded_directory_entry_size(entry)";
      }
      {
        label = "mutating EROFS";
        needle = "NinePRequestKind::Mutating(_) => return ninep_error(request.tag, NINEP_EROFS)";
      }
      {
        label = "unknown ENOSYS";
        needle = "NinePRequestKind::Unknown { .. } => return ninep_error(request.tag, NINEP_ENOSYS)";
      }
      {
        label = "malformed request";
        needle = "NinePRequestKind::Malformed { io_error }";
      }
      {
        label = "version clears fid table";
        needle = "self.fids.clear();";
      }
      {
        label = "directory cache";
        needle = "entries: self.tree.readdir(path)?";
      }
      {
        label = "opened fid walk rejection";
        needle = "NinePServerError::FidAlreadyOpen";
      }
      {
        label = "xattr target handling";
        needle = "NinePFidTarget::Xattr";
      }
      {
        label = "snapshot restore";
        needle = "pub fn restore_snapshot";
      }
      {
        label = "open kind persisted";
        needle = "open_kind: state.open.as_ref().map(NinePOpenHandle::kind)";
      }
      {
        label = "duplicate fid validation";
        needle = "NinePServerError::DuplicateFid";
      }
      {
        label = "invalid fid snapshot validation";
        needle = "NinePServerError::InvalidFidSnapshot";
      }
      {
        label = "read-only errno";
        needle = "pub const NINEP_EROFS: u32 = 30";
      }
      {
        label = "unknown errno";
        needle = "pub const NINEP_ENOSYS: u32 = 38";
      }
      {
        label = "malformed errno";
        needle = "pub const NINEP_EINVAL: u32 = 22";
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
        label = "wall-clock API";
        needle = "SystemTime";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "randomized hasher";
        needle = "RandomState";
      }
      {
        label = "panic unwrap";
        needle = ".unwrap()";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "session exported";
        needle = "NinePSession";
      }
      {
        label = "request exported";
        needle = "NinePRequest";
      }
      {
        label = "response exported";
        needle = "NinePResponse";
      }
      {
        label = "snapshot exported";
        needle = "NinePSessionSnapshot";
      }
      {
        label = "error constants exported";
        needle = "NINEP_EROFS";
      }
    ]
    ++ failuresFor "crates/crucible/tests/ninep_session_lifecycle.rs" focusedTest [
      {
        label = "focused lifecycle test";
        needle = "deterministic 9p session request handling and fid restore";
      }
      {
        label = "read traverse test";
        needle = "session_handles_read_traverse_metadata_and_clunk_requests";
      }
      {
        label = "readdir restore test";
        needle = "readdir_uses_cached_sorted_directory_and_snapshot_restore_rebuilds_it";
      }
      {
        label = "readdir byte budget test";
        needle = "readdir_count_is_an_encoded_payload_byte_budget";
      }
      {
        label = "error boundary test";
        needle = "mutating_unknown_and_malformed_requests_fail_with_typed_errno";
      }
      {
        label = "msize mutation guard test";
        needle = "msize_enforcement_happens_before_request_state_mutation";
      }
      {
        label = "read payload limit test";
        needle = "read_payload_is_limited_by_negotiated_msize";
      }
      {
        label = "walk fid rules test";
        needle = "walk_supports_same_fid_and_rejects_opened_source_fids";
      }
      {
        label = "version reset test";
        needle = "version_negotiation_resets_fid_state";
      }
      {
        label = "xattrwalk test";
        needle = "xattrwalk_creates_deterministic_empty_xattr_fid";
      }
      {
        label = "snapshot rejection test";
        needle = "snapshot_restore_rejects_forged_fids_msize_and_open_kinds";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/ninep_session_lifecycle.rs" focusedTest [
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
        label = "phase3 exposes 9p session check";
        needle = "ninePSessionLifecycle = import ./phase3-ninep-session-lifecycle.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase3 9p session lifecycle check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase3-ninep-session-lifecycle";
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
          name = "run-ninep-session-lifecycle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-ninep-session-lifecycle-target" \
              -p crucible \
              --test ninep_session_lifecycle \
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
            component=crucible-ninep-session-lifecycle
            gate=gate:abi-conformance,gate:any-guest,gate:replay-oracle
            request_set=read-traverse
            mutating=EROFS
            unknown=ENOSYS
            malformed=EINVAL-or-EIO
            fid_state=snapshot-restore
            RESULT
          '';
        }
      ];
    }
