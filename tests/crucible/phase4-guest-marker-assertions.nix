{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestMarkerAssertions",
  taskIds ? ["T-ASRT-6"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  guestMarkerAssertionsTest = builtins.readFile ../../crates/crucible/tests/guest_marker_assertions.rs;
  assertionDoc = builtins.readFile ../../docs/rfcs/0010-crucible/18-assertions-properties.md;
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

  # Character-exact scrub of Rust comments and string literals. The fold is
  # chunked per source line (each chunk keeps its trailing newline, and the
  # parser state — mode/depth/skip — threads across chunks) with the output
  # string forced after every chunk. A whole-file per-character fold builds a
  # haystack-deep chain of unforced `+` thunks and overflows the evaluator
  # stack on large sources.
  scrubCommentsAndStrings = content: let
    scrubChunk = chunkState: chunk: let
      length = builtins.stringLength chunk;
      charAt = index: builtins.substring index 1 chunk;
      indexes = builtins.genList (index: index) length;
      folded = builtins.foldl' step chunkState indexes;
      step = state: index:
        if state.skip
        then
          state
          // {
            skip = false;
          }
        else let
          ch = charAt index;
          next =
            if (index + 1) < length
            then charAt (index + 1)
            else "";
        in
        if state.mode == "code"
        then
          if ch == "/" && next == "/"
          then
            state
            // {
              out = state.out + "  ";
              mode = "line";
              skip = true;
            }
          else if ch == "/" && next == "*"
          then
            state
            // {
              out = state.out + "  ";
              mode = "block";
              depth = 1;
              skip = true;
            }
          else if ch == "\""
          then
            state
            // {
              out = state.out + " ";
              mode = "string";
            }
          else
            state
            // {
              out = state.out + ch;
            }
        else if state.mode == "line"
        then
          if ch == "\n"
          then
            state
            // {
              out = state.out + "\n";
              mode = "code";
            }
          else
            state
            // {
              out = state.out + " ";
            }
        else if state.mode == "block"
        then
          if ch == "/" && next == "*"
          then
            state
            // {
              out = state.out + "  ";
              depth = state.depth + 1;
              skip = true;
            }
          else if ch == "*" && next == "/"
          then
            state
            // {
              out = state.out + "  ";
              mode =
                if state.depth == 1
                then "code"
                else "block";
              depth =
                if state.depth == 1
                then 0
                else state.depth - 1;
              skip = true;
            }
          else
            state
            // {
              out = state.out + (
                if ch == "\n"
                then "\n"
                else " "
              );
            }
        else if ch == "\\" && next != ""
        then
          state
          // {
            out = state.out + " " + (
              if next == "\n"
              then "\n"
              else " "
            );
            skip = true;
          }
        else if ch == "\""
        then
          state
          // {
            out = state.out + " ";
            mode = "code";
          }
        else
          state
          // {
            out = state.out + (
              if ch == "\n"
              then "\n"
              else " "
            );
          };
    in
      # Force the accumulated output flat before the next chunk so thunk
      # depth stays bounded by the longest line, not the whole file.
      builtins.seq (builtins.stringLength folded.out) folded;
    lines = lib.splitString "\n" content;
    lineCount = builtins.length lines;
    chunkAt = index:
      builtins.elemAt lines index
      + (
        if index + 1 < lineCount
        then "\n"
        else ""
      );
    result =
      builtins.foldl'
      (state: index: scrubChunk state (chunkAt index))
      {
        out = "";
        mode = "code";
        depth = 0;
        skip = false;
      }
      (builtins.genList (index: index) lineCount);
  in
    result.out;

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
    failuresFor "docs/rfcs/0010-crucible/18-assertions-properties.md" assertionDoc [
      {
        label = "T-ASRT-6 checked off";
        needle = "- [x] **T-ASRT-6**";
      }
      {
        label = "T-ASRT-6 completion note";
        needle = "Completed by `checks.crucible.phase4.guestMarkerAssertions`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "guest assertion kind enum";
        needle = "pub enum GuestAssertionKind";
      }
      {
        label = "guest assertion marker payload";
        needle = "pub struct GuestAssertionMarker";
      }
      {
        label = "guest assertion detail payload";
        needle = "pub struct GuestAssertionDetail";
      }
      {
        label = "payload id field";
        needle = "pub id: AssertionId";
      }
      {
        label = "payload kind field";
        needle = "pub kind: GuestAssertionKind";
      }
      {
        label = "payload condition field";
        needle = "pub condition: bool";
      }
      {
        label = "payload must-hit field";
        needle = "pub must_hit: bool";
      }
      {
        label = "payload details field";
        needle = "pub details: Vec<GuestAssertionDetail>";
      }
      {
        label = "payload location field";
        needle = "pub location: String";
      }
      {
        label = "observable assertion marker event";
        needle = "ObservableEventPayload::GuestAssertionMarker";
      }
      {
        label = "guest assertion marker constructor";
        needle = "pub fn guest_assertion_marker";
      }
      {
        label = "always guest marker kind";
        needle = "GuestAssertionKind::Always";
      }
      {
        label = "sometimes guest marker kind";
        needle = "GuestAssertionKind::Sometimes";
      }
      {
        label = "reachable guest marker kind";
        needle = "GuestAssertionKind::Reachable";
      }
      {
        label = "unreachable guest marker kind";
        needle = "GuestAssertionKind::Unreachable";
      }
      {
        label = "guest marker assertion fold";
        needle = "fn observe_guest_marker_assertions";
      }
      {
        label = "guest marker finalization";
        needle = "fn finalize_guest_marker_assertion_state";
      }
      {
        label = "guest assertion catalog preseed";
        needle = "with_guest_assertion_catalog";
      }
      {
        label = "world-derived white-box policy";
        needle = "white_box_policies";
      }
      {
        label = "assertion marker stays out of trigger guest-marker leaf";
        needle = "ObservableEventPayload::GuestAssertionMarker { .. } => false";
      }
      {
        label = "guest marker kind mismatch diagnostic";
        needle = "guest marker assertion kind mismatch";
      }
      {
        label = "unified verdict construction";
        needle = "AssertionRunVerdict::failed";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
      {
        label = "guest assertion marker export";
        needle = "GuestAssertionMarker";
      }
      {
        label = "guest assertion kind export";
        needle = "GuestAssertionKind";
      }
      {
        label = "guest assertion detail export";
        needle = "GuestAssertionDetail";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_marker_assertions.rs" guestMarkerAssertionsTest [
      {
        label = "payload field test";
        needle = "guest_assertion_marker_payload_carries_finalize_fields";
      }
      {
        label = "unified report test";
        needle = "guest_marker_assertions_fold_into_unified_report";
      }
      {
        label = "catalog finalization test";
        needle = "catalog_declared_guest_markers_finalize_without_emitted_events";
      }
      {
        label = "five quantifier guest marker predicate test";
        needle = "guest_marker_predicates_work_in_all_five_property_quantifiers";
      }
      {
        label = "assertion marker trigger isolation test";
        needle = "assertion_markers_do_not_fire_guest_marker_triggers";
      }
      {
        label = "current payload terminal reason test";
        needle = "terminal_marker_reasons_use_current_payload_details";
      }
      {
        label = "terminal outcome immutability test";
        needle = "terminal_marker_outcome_ignores_later_payload_updates";
      }
      {
        label = "kind mismatch diagnostic test";
        needle = "guest_marker_catalog_kind_mismatch_is_reported";
      }
      {
        label = "disabled node rejection test";
        needle = "guest_marker_assertions_ignore_disabled_white_box_nodes";
      }
      {
        label = "observational static test";
        needle = "guest_marker_assertion_implementation_is_observational_and_deterministic";
      }
      {
        label = "must-hit payload assertion";
        needle = "marker.must_hit";
      }
      {
        label = "details payload assertion";
        needle = "marker.details";
      }
      {
        label = "location payload assertion";
        needle = "marker.location";
      }
      {
        label = "catalog must-hit assertion";
        needle = "catalog-reachable-fail";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 guest marker assertions check import";
        needle = "guestMarkerAssertions = import ./phase4-guest-marker-assertions.nix";
      }
      {
        label = "phase4 guest marker assertions attr path";
        needle = "attrPath = \"checks.crucible.phase4.guestMarkerAssertions\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/trigger.rs" (scrubCommentsAndStrings trigger) [
      {
        label = "host wall-clock dependency";
        needle = "SystemTime";
      }
      {
        label = "host instant dependency";
        needle = "time::Instant";
      }
      {
        label = "std time dependency";
        needle = "std::time";
      }
      {
        label = "unordered hash map";
        needle = "HashMap";
      }
      {
        label = "unordered hash set";
        needle = "HashSet";
      }
      {
        label = "thread-local RNG";
        needle = "thread_rng";
      }
      {
        label = "runtime RNG import";
        needle = "rand::";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/guest_marker_assertions.rs" guestMarkerAssertionsTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then throw "crucible phase4 guest-marker-assertions check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-marker-assertions";
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
          name = "run-guest-marker-assertions";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-marker-assertions-target" \
              -p crucible \
              --test guest_marker_assertions \
              --test guest_marker_condition_leaf \
              --test host_side_assertions \
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
            guest_marker_assertions_unified=true
            RESULT
          '';
        }
      ];
    }
