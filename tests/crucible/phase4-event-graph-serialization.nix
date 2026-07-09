{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.eventGraphSerialization",
  taskIds ? ["T-TRIG-18"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  trigger = builtins.readFile ../../crates/crucible/src/trigger.rs;
  model = builtins.readFile ../../crates/crucible/src/model.rs;
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  serializationTest = builtins.readFile ../../crates/crucible/tests/event_graph_serialization.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
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
  serializationSources = builtins.concatStringsSep "\n" [
    (scrubCommentsAndStrings trigger)
    (scrubCommentsAndStrings model)
    (scrubCommentsAndStrings libRs)
    (scrubCommentsAndStrings serializationTest)
  ];
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-18 checked off";
        needle = "- [x] **T-TRIG-18**";
      }
      {
        label = "T-TRIG-18 completion note";
        needle = "Completed by `checks.crucible.phase4.eventGraphSerialization`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "event graph builder type";
        needle = "pub struct EventGraphBuilder";
      }
      {
        label = "event graph builder entrypoint";
        needle = "pub fn builder() -> EventGraphBuilder";
      }
      {
        label = "assertion-aware builder validation";
        needle = "pub fn build_with_assertions_for_world";
      }
      {
        label = "event builder type";
        needle = "pub struct EventGraphEventBuilder";
      }
      {
        label = "event builder action finalizer";
        needle = "pub fn action(mut self, action: Action) -> EventGraphBuilder";
      }
      {
        label = "inject-fault action constructor";
        needle = "pub fn inject_fault";
      }
      {
        label = "pass action constructor";
        needle = "pub const fn pass() -> Self";
      }
      {
        label = "group action constructor";
        needle = "pub fn group(actions: Vec<Action>) -> Self";
      }
      {
        label = "graph-native static evaluation schedule";
        needle = "fn graph_static_evaluation_times";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "Plan kind discriminates scheduled and graph forms";
        needle = "enum PlanKind";
      }
      {
        label = "Plan carries event graph";
        needle = "EventGraph { graph: EventGraph }";
      }
      {
        label = "assertion-aware graph Plan constructor";
        needle = "pub fn from_event_graph_with_assertions_for_world";
      }
      {
        label = "assertion-aware graph Plan TOML parser";
        needle = "pub fn from_canonical_toml_with_assertions_for_world";
      }
      {
        label = "assertion-aware graph Plan binary parser";
        needle = "pub fn from_compact_binary_with_assertions_for_world";
      }
      {
        label = "graph Plan accessor";
        needle = "pub fn event_graph(&self) -> Option<&EventGraph>";
      }
      {
        label = "scenario composition validates graph Plan with properties";
        needle = "fn validate_event_graph_plan";
      }
      {
        label = "Plan-kind canonical material";
        needle = "fn plan_kind_material";
      }
      {
        label = "event graph canonical material";
        needle = "fn event_graph_plan_material";
      }
      {
        label = "event graph TOML discriminant";
        needle = "PlanKindToml::EventGraph";
      }
      {
        label = "event binary writer";
        needle = "fn write_event_binary";
      }
      {
        label = "event binary reader";
        needle = "fn read_event_binary";
      }
      {
        label = "action binary writer";
        needle = "fn write_action_binary";
      }
      {
        label = "action binary reader";
        needle = "fn read_action_binary";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libRs [
      {
        label = "EventGraphBuilder exported";
        needle = "EventGraphBuilder";
      }
      {
        label = "EventGraphEventBuilder exported";
        needle = "EventGraphEventBuilder";
      }
    ]
    ++ failuresFor "crates/crucible/tests/event_graph_serialization.rs" serializationTest [
      {
        label = "builder validates before hashing test";
        needle = "event_graph_builder_validates_before_plan_hashing";
      }
      {
        label = "Plan TOML and binary round-trip test";
        needle = "event_graph_plan_round_trips_through_toml_and_binary";
      }
      {
        label = "ScenarioDef Plan component test";
        needle = "graph_plan_is_the_scenario_plan_component";
      }
      {
        label = "assertion namespace validation test";
        needle = "assertion_references_are_validated_when_plan_enters_scenario_form";
      }
      {
        label = "standalone Plan TOML event array";
        needle = "[[event]]";
      }
      {
        label = "ScenarioDef nested Plan event array";
        needle = "[[plan.event]]";
      }
      {
        label = "canonical Plan hash assertion";
        needle = "ContentHash::from_canonical_material";
      }
      {
        label = "component orthogonality assertion";
        needle = "changed_properties_form.plan().content_hash()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes event graph serialization check";
        needle = "eventGraphSerialization = import ./phase4-event-graph-serialization.nix";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "stale T-TRIG-18 remaining-work prose";
        needle = "remain T-TRIG-18";
      }
    ]
    ++ forbiddenFor "event graph serialization sources" serializationSources [
      {
        label = "trigger action decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "host wall clock";
        needle = "std::time";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
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
  then throw "crucible phase4 event-graph-serialization check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-event-graph-serialization";
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
          name = "run-event-graph-serialization";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-event-graph-serialization-target" \
              -p crucible \
              --test event_graph_serialization \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            {
              echo "attr=${attrPath}"
              echo "tasks=${taskList}"
              echo "gate=phase4-event-graph-serialization"
              echo "event_graph_builder=implemented-T-TRIG-18"
              echo "plan_component_event_graph=implemented-T-TRIG-18"
              echo "canonical_toml_round_trip=true"
              echo "compact_binary_round_trip=true"
              echo "component_orthogonality=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
