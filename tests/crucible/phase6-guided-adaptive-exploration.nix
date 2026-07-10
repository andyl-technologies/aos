{
  pkgs,
  lib,
  attrPath,
  taskIds ? [],
  openTaskIds ? [],
  gateName,
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-6Ig56XHLaW8Ow70BXh/oVSblxDoU4dkK5XqZJmd2RUw=";
  };

  advancedDoc = builtins.readFile ../../docs/rfcs/0010-crucible/22-advanced-features.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = builtins.readFile ../../crates/crucible/src/lib.rs;
  guidedTest = builtins.readFile ../../crates/crucible/tests/gate_guided_adaptive_exploration.rs;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  allTaskIds = taskIds ++ openTaskIds;
  taskId =
    if builtins.length allTaskIds == 1
    then builtins.head allTaskIds
    else throw "guided/adaptive exploration check requires exactly one completed or open task id";

  taskSpec =
    {
      T-ADV-17 = {
        testFilter = "gate_guidance_signals_are_fixed_point_readers_only";
        result = "partial_guidance=fixed-point-scaffolding-only";
        docNeedles = [
          {
            label = "T-ADV-17 remains open";
            needle = "- [ ] **T-ADV-17**";
          }
          {
            label = "guidance partial-evidence note";
            needle = "Partial evidence from `checks.crucible.phase6.guidanceSignals`";
          }
          {
            label = "guidance owned-rarity-table blocker";
            needle = "owned, deterministically maintained rarity table";
          }
        ];
        modelNeedles = [
          {
            label = "guidance trait";
            needle = "pub trait GuidanceSignal";
          }
          {
            label = "coverage guidance";
            needle = "pub struct CoverageGuidanceSignal";
          }
          {
            label = "novelty guidance";
            needle = "pub struct NoveltyRarityGuidanceSignal";
          }
          {
            label = "assertion proximity guidance";
            needle = "pub struct AssertionProximityGuidanceSignal";
          }
          {
            label = "coverage search key";
            needle = "pub fn search_order_key";
          }
        ];
        libNeedles = [
          {
            label = "guidance export";
            needle = "GuidanceSignal";
          }
        ];
        testNeedles = [
          {
            label = "guidance test";
            needle = "gate_guidance_signals_are_fixed_point_readers_only";
          }
          {
            label = "fixed-point assertion";
            needle = "GuidanceScore";
          }
        ];
      };
      T-ADV-18 = {
        testFilter = "gate_adaptive_strategy_selection_is_deterministic_and_fair";
        result = "partial_adaptive=non-ucb-selection-scaffolding";
        docNeedles = [
          {
            label = "T-ADV-18 remains open";
            needle = "- [ ] **T-ADV-18**";
          }
          {
            label = "adaptive partial-evidence note";
            needle = "Partial evidence from `checks.crucible.phase6.adaptiveStrategies`";
          }
          {
            label = "adaptive UCB blocker";
            needle = "required deterministic UCB default";
          }
        ];
        modelNeedles = [
          {
            label = "adaptive config";
            needle = "pub struct AdaptiveStrategyConfig";
          }
          {
            label = "adaptive credit";
            needle = "pub struct AdaptiveStrategyCredit";
          }
          {
            label = "adaptive selector";
            needle = "pub fn run_adaptive_strategy_selection";
          }
          {
            label = "content-address graph fingerprint";
            needle = "fn adaptive_strategy_graph_fingerprint";
          }
        ];
        libNeedles = [
          {
            label = "adaptive export";
            needle = "AdaptiveStrategyConfig";
          }
        ];
        testNeedles = [
          {
            label = "adaptive test";
            needle = "gate_adaptive_strategy_selection_is_deterministic_and_fair";
          }
          {
            label = "content-address credit";
            needle = "AdaptiveStrategyCredit";
          }
        ];
      };
      T-ADV-19 = {
        testFilter = "gate_guidance_determinism_lint_rejects_float_scores";
        result = "partial_lint=synthetic-input-only";
        docNeedles = [
          {
            label = "T-ADV-19 remains open";
            needle = "- [ ] **T-ADV-19**";
          }
          {
            label = "guidance lint partial-evidence note";
            needle = "Partial evidence from `checks.crucible.phase6.guidanceDeterminismLint`";
          }
          {
            label = "guidance actual-source lint blocker";
            needle = "comment/string-aware scan of the actual signal and bandit ordering sources";
          }
        ];
        modelNeedles = [
          {
            label = "guidance lint";
            needle = "pub fn lint_guidance_determinism_source";
          }
          {
            label = "lint report";
            needle = "pub struct GuidanceDeterminismLintReport";
          }
        ];
        libNeedles = [
          {
            label = "lint export";
            needle = "lint_guidance_determinism_source";
          }
        ];
        testNeedles = [
          {
            label = "lint test";
            needle = "gate_guidance_determinism_lint_rejects_float_scores";
          }
        ];
      };
      T-ADV-20 = {
        testFilter = "gate_preemption_branching_records_oracle_validated_children";
        result = "partial_preemption=no-partial-order-reduction-proof";
        docNeedles = [
          {
            label = "T-ADV-20 remains open";
            needle = "- [ ] **T-ADV-20**";
          }
          {
            label = "preemption partial-evidence note";
            needle = "Partial evidence from `checks.crucible.phase6.preemptionBranching`";
          }
          {
            label = "preemption reduction blocker";
            needle = "the current gate explicitly disables reduction";
          }
        ];
        modelNeedles = [
          {
            label = "preemption branch config";
            needle = "pub struct PreemptionBranchConfig";
          }
          {
            label = "preemption graph branch";
            needle = "pub fn branch_preemptions";
          }
          {
            label = "vcpu switch branch";
            needle = "PreemptionKind::VcpuSwitch";
          }
          {
            label = "interrupt branch";
            needle = "PreemptionKind::InterruptAt";
          }
        ];
        libNeedles = [
          {
            label = "preemption branch export";
            needle = "PreemptionBranchConfig";
          }
        ];
        testNeedles = [
          {
            label = "preemption test";
            needle = "gate_preemption_branching_records_oracle_validated_children";
          }
          {
            label = "preemption decision assertion";
            needle = "Decision::Preemption";
          }
        ];
      };
      T-ADV-21 = {
        testFilter = "gate_app_random_branching_is_optional_and_bounded";
        result = "partial_app_random=caller-supplied-sites-unbounded-samples";
        docNeedles = [
          {
            label = "T-ADV-21 remains open";
            needle = "- [ ] **T-ADV-21**";
          }
          {
            label = "app-random partial-evidence note";
            needle = "Partial evidence from `checks.crucible.phase6.appRandomBranching`";
          }
          {
            label = "app-random observed-site blocker";
            needle = "deriving sites from recorded observations";
          }
        ];
        modelNeedles = [
          {
            label = "app-random branch config";
            needle = "pub struct AppRandomBranchConfig";
          }
          {
            label = "app-random draw site";
            needle = "pub struct AppRandomDrawSite";
          }
          {
            label = "app-random graph branch";
            needle = "pub fn branch_app_random";
          }
        ];
        libNeedles = [
          {
            label = "app-random branch export";
            needle = "AppRandomBranchConfig";
          }
        ];
        testNeedles = [
          {
            label = "app-random test";
            needle = "gate_app_random_branching_is_optional_and_bounded";
          }
          {
            label = "app-random decision assertion";
            needle = "Decision::AppRandom";
          }
        ];
      };
    }
    .${taskId};

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

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/rfcs/0010-crucible/22-advanced-features.md" advancedDoc taskSpec.docNeedles
    ++ failuresFor "crates/crucible/src/model.rs" temporalGraph taskSpec.modelNeedles
    ++ failuresFor "crates/crucible/src/lib.rs" libRs taskSpec.libNeedles
    ++ failuresFor "crates/crucible/tests/gate_guided_adaptive_exploration.rs" guidedTest taskSpec.testNeedles
    ++ forbiddenFailuresFor "crates/crucible/tests/gate_guided_adaptive_exploration.rs" guidedTest [
      {
        label = "ignored red placeholder";
        needle = "#[ignore";
      }
      {
        label = "placeholder pending panic";
        needle = "implementation is pending";
      }
    ];
in
  if failures != []
  then throw "crucible phase6 guided/adaptive exploration check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase6-guided-adaptive-exploration";
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
          name = "run-guided-adaptive-exploration";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guided-adaptive-exploration-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --test gate_guided_adaptive_exploration \
              ${taskSpec.testFilter} \
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
            open_tasks=${openTaskList}
            gate=${gateName}
            ${taskSpec.result}
            RESULT
          '';
        }
      ];
    }
