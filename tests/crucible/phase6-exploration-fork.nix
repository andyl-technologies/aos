{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.explorationFork",
  taskIds ? ["T-ADV-3"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  sessionLib = import ./_crucible-session-source.nix {inherit lib;};
  forkGateTest = builtins.readFile ../../crates/crucible-session/tests/gate_exploration_fork.rs;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

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

  indexOf = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
    matches =
      builtins.filter (
        index: builtins.substring index needleLen haystack == needle
      )
      indexes;
  in
    if matches == []
    then null
    else builtins.head matches;

  sliceFromUntil = content: startNeedle: endNeedle: let
    start = indexOf startNeedle content;
    tailStart = start + builtins.stringLength startNeedle;
    tail = builtins.substring tailStart (builtins.stringLength content - tailStart) content;
    end = indexOf endNeedle tail;
  in
    if start == null
    then ""
    else if end == null
    then startNeedle + tail
    else startNeedle + builtins.substring 0 end tail;

  defaultExplorationForkBlock =
    sliceFromUntil
    defaultChecks
    "    explorationFork = greenBeforeAdvance {"
    "    gates = {";

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc [
      {
        label = "T-ADV-3 checked off";
        needle = "- [x] **T-ADV-3**";
      }
      {
        label = "T-ADV-3 completion note";
        needle = "Completed by `checks.crucible.phase6.explorationFork`";
      }
    ]
    ++ failuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "session fork mailbox capacity";
        needle = "pub const SESSION_FORK_MAILBOX_CAPACITY";
      }
      {
        label = "session fork record";
        needle = "pub struct SessionForkRecord";
      }
      {
        label = "session fork result";
        needle = "pub struct SessionFork";
      }
      {
        label = "child fork API";
        needle = "pub fn fork_child";
      }
      {
        label = "temporal graph fork delegation";
        needle = "self.graph.fork(base, decisions)?";
      }
      {
        label = "child actor construction";
        needle = "SessionActor::new(child_engine, receiver)";
      }
      {
        label = "loaded and running rejection";
        needle = ''operation: "fork_child"'';
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-session/src/lib.rs" sessionLib [
      {
        label = "detached live debug mode";
        needle = "detach";
      }
      {
        label = "fork-specific qemu path";
        needle = "live-non-deterministic";
      }
    ]
    ++ failuresFor "crates/crucible-session/tests/gate_exploration_fork.rs" forkGateTest [
      {
        label = "non-tip child fork test";
        needle = "fork_child_uses_temporal_graph_fork_and_independent_child_actor";
      }
      {
        label = "loaded/running rejection test";
        needle = "fork_child_rejects_loaded_and_running_parent_without_pause";
      }
      {
        label = "stopped parent fork test";
        needle = "stopped_parent_can_fork_from_final_checkpoint_without_mutation";
      }
      {
        label = "thin branch checkpoint assertion";
        needle = "fork.branch_checkpoint.kind, CheckpointKind::Thin";
      }
      {
        label = "parent immutability assertion";
        needle = "assert_eq!(parent.snapshot(), parent_before)";
      }
      {
        label = "child branch configuration assertion";
        needle = "fork.child_actor.engine().configuration()";
      }
      {
        label = "independent child actor run";
        needle = "fork.child_actor.run()";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible-session/tests/gate_exploration_fork.rs" forkGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix explorationFork block" defaultExplorationForkBlock [
      {
        label = "phase6 exploration fork green wrapper";
        needle = "explorationFork = greenBeforeAdvance";
      }
      {
        label = "phase6 exploration fork import";
        needle = "gate = import ./phase6-exploration-fork.nix";
      }
      {
        label = "phase6 exploration fork attr path";
        needle = "checks.crucible.phase6.explorationFork";
      }
      {
        label = "phase6 exploration fork task id";
        needle = ''taskIds = ["T-ADV-3"]'';
      }
      {
        label = "phase4 replay oracle raw dependency";
        needle = "\n          phase4.gates.replayOracle.rawGate\n";
      }
      {
        label = "phase4 e2e determinism raw dependency";
        needle = "\n          phase4.gates.e2eDeterminism.rawGate\n";
      }
      {
        label = "phase6 lifecycle raw dependency";
        needle = "\n          phase6.explorationLifecycle.rawGate\n";
      }
      {
        label = "phase6 savevm completeness raw dependency";
        needle = "\n          phase6.savevmCompleteness.rawGate\n";
      }
      {
        label = "phase4 replay oracle green dependency";
        needle = "\n        phase4.gates.replayOracle\n";
      }
      {
        label = "phase4 e2e determinism green dependency";
        needle = "\n        phase4.gates.e2eDeterminism\n";
      }
      {
        label = "phase6 lifecycle green dependency";
        needle = "\n        phase6.explorationLifecycle\n";
      }
      {
        label = "phase6 savevm completeness green dependency";
        needle = "\n        phase6.savevmCompleteness\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 exploration fork check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-exploration-fork";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

      DEPENDENCIES = builtins.concatStringsSep ":" dependencies;

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
            set -eu
            : "$DEPENDENCIES"
            export CARGO_HOME="$TMPDIR/cargo-home"
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
          name = "run-exploration-fork";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-exploration-fork-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-session \
              --test gate_exploration_fork \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
                        set -eu
                        mkdir -p "$out"
                        cat > "$out/result" <<RESULT
                        PASS
            check=${attrPath}
            tasks=${taskList}
            fork=temporal-graph-branch,independent-child-session
            rust_test=crucible-session::gate_exploration_fork
            RESULT
          '';
        }
      ];
    }
