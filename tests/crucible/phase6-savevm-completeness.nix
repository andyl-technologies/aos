{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase6.savevmCompleteness",
  taskIds ? ["T-ADV-6"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  savevmGateTest = builtins.readFile ../../crates/crucible/tests/gate_savevm_completeness.rs;
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

  defaultSavevmCompletenessBlock =
    sliceFromUntil
    defaultChecks
    "    savevmCompleteness = greenBeforeAdvance {"
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
        label = "T-ADV-6 checked off";
        needle = "- [x] **T-ADV-6**";
      }
      {
        label = "T-ADV-6 completion note";
        needle = "Completed by `checks.crucible.phase6.savevmCompleteness`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph [
      {
        label = "savevm hedge type";
        needle = "pub struct SavevmCompletenessHedge";
      }
      {
        label = "unreliable-device hedge constructor";
        needle = "pub fn with_unreliable_devices<I>(devices: I) -> Self";
      }
      {
        label = "global thin fallback constructor";
        needle = "pub fn thin_replay_until_full_s3() -> Self";
      }
      {
        label = "hedged snapshot cache API";
        needle = "pub fn cache_snapshot_with_savevm_hedge(";
      }
      {
        label = "hedged materialization API";
        needle = "pub fn materialize_checkpoint_with_savevm_hedge(";
      }
      {
        label = "hedged hot materialization API";
        needle = "pub fn materialize_hot_checkpoint_with_savevm_hedge(";
      }
      {
        label = "user-facing save API";
        needle = "pub fn save<S>(";
      }
      {
        label = "save uses fat materialization";
        needle = "let checkpoint = self.save_checkpoint(configuration).map_err";
      }
      {
        label = "save checkpoint materializes fat cache";
        needle = "self.materialize_checkpoint(configuration)";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_savevm_completeness.rs" savevmGateTest [
      {
        label = "unreliable snapshots stay thin test";
        needle = "gate_savevm_completeness_keeps_unreliable_snapshots_thin";
      }
      {
        label = "global fallback thin replay test";
        needle = "gate_savevm_completeness_global_fallback_evicts_to_thin_replay";
      }
      {
        label = "save checkpoint key test";
        needle = "gate_savevm_completeness_save_persists_fat_checkpoint_keyed_by_configuration";
      }
      {
        label = "unreliable-device hedge use";
        needle = "SavevmCompletenessHedge::with_unreliable_devices";
      }
      {
        label = "direct hedged materialization";
        needle = "direct_graph.materialize_checkpoint_with_savevm_hedge";
      }
      {
        label = "unreliable hedge disables fat default";
        needle = "assert!(!unreliable.fat_snapshot_default())";
      }
      {
        label = "thin fallback use";
        needle = "SavevmCompletenessHedge::thin_replay_until_full_s3";
      }
      {
        label = "save persists cache key";
        needle = "save.store_keys.cached_snapshots.contains_key(&target.id())";
      }
      {
        label = "thin source-of-truth assertion";
        needle = "save should retain the thin source-of-truth checkpoint";
      }
    ]
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_savevm_completeness.rs" savevmGateTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix savevmCompleteness block" defaultSavevmCompletenessBlock [
      {
        label = "phase6 savevm completeness green wrapper";
        needle = "savevmCompleteness = greenBeforeAdvance";
      }
      {
        label = "phase6 savevm completeness import";
        needle = "gate = import ./phase6-savevm-completeness.nix";
      }
      {
        label = "phase6 savevm completeness attr path";
        needle = "checks.crucible.phase6.savevmCompleteness";
      }
      {
        label = "phase6 savevm completeness task id";
        needle = ''taskIds = ["T-ADV-6"]'';
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
        label = "phase6 restore strategies raw dependency";
        needle = "\n          phase6.restoreStrategies.rawGate\n";
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
        label = "phase6 restore strategies green dependency";
        needle = "\n        phase6.restoreStrategies\n";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 savevm completeness check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-savevm-completeness";
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
          name = "run-savevm-completeness";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-savevm-completeness-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_savevm_completeness \
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
            savevm=thin-on-unreliable,fat-save-by-config-id
            rust_test=crucible::gate_savevm_completeness
            RESULT
          '';
        }
      ];
    }
