{
  pkgs,
  lib,
  attrPath,
  gateName,
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  explorationPage = builtins.readFile ../../docs/engineering/crucible/exploration.md;
  temporalGraph = import ./_crucible-model-source.nix {inherit lib;};
  libRs = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/crucible-engine/src/lib.rs;
  };
  guidedTest = builtins.readFile ../../crates/crucible/crucible-engine/tests/gate_guided_adaptive_exploration.rs;
  guidanceLintTest = builtins.readFile ../../crates/crucible/crucible-test-support/tests/support/harness_lint/guidance.rs;

  # One file serves five Phase 6 gates; each instance selects its proof by gate name.
  gateSpecs = {
    "gate:guidance-signals" = {
      testFilter = "gate_guidance_signals_are_fixed_point_readers_only";
      result = "guidance=integrated-fixed-point-coverage+rarity+assertion-proximity";
      docNeedles = [
        {
          label = "guidance integrated search proof";
          needle = "`TemporalGraph::search_with_guidance`";
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
        {
          label = "guidance search state";
          needle = "pub struct GuidanceSearchState";
        }
        {
          label = "integrated guidance search";
          needle = "pub fn search_with_guidance";
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
        {
          label = "integrated search test";
          needle = "gate_guidance_signals_are_fixed_point_readers_only_in_integrated_search";
        }
      ];
    };
    "gate:adaptive-strategies" = {
      testFilter = "gate_adaptive_strategy_selection_is_deterministic_and_fair";
      result = "adaptive=deterministic-fixed-point-ucb+integrated-campaign+realized-credit+fairness";
      docNeedles = [
        {
          label = "adaptive integrated campaign proof";
          needle = "`TemporalGraph::search_adaptive_campaign`";
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
        {
          label = "adaptive campaign config";
          needle = "pub struct AdaptiveCampaignConfig";
        }
        {
          label = "integrated adaptive search";
          needle = "pub fn search_adaptive_campaign";
        }
        {
          label = "integer UCB implementation";
          needle = "fn integer_square_root";
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
        {
          label = "integrated adaptive test";
          needle = "gate_adaptive_strategy_selection_is_deterministic_and_fair_in_integrated_campaign";
        }
      ];
    };
    "gate:guidance-determinism-lint" = {
      testFilter = "gate_guidance_determinism_lint_rejects_float_scores";
      result = "guidance_lint=actual-sources+comment-string-aware+mutation-negative";
      docNeedles = [
        {
          label = "guidance actual-source lint proof";
          needle = "is the comment- and string-aware token scan";
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
      harnessNeedles = [
        {
          label = "actual-source guidance lint";
          needle = "guidance_ordering_float_failures";
        }
        {
          label = "guidance lint mutation negative";
          needle = "rejects_float_types_but_ignores_comments_and_strings";
        }
        {
          label = "adaptive campaign source coverage";
          needle = "crucible/crucible-engine/src/model/adaptive_campaign.rs";
        }
      ];
    };
    "gate:preemption-branching" = {
      testFilter = "gate_preemption_branching";
      result = "preemption=bounded-single-vcpu+partial-order-reduction+content-addressed-oracle-validated-children";
      docNeedles = [
        {
          label = "preemption reduction proof";
          needle = "reduction can collapse commuting preemptions";
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
          label = "covered representative materialization";
          needle = "fn materialize_preemption_branches";
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
          label = "preemption child test";
          needle = "gate_preemption_branching_records_oracle_validated_children";
        }
        {
          label = "preemption POR test";
          needle = "gate_preemption_branching_reduces_commuting_single_vcpu_preemptions";
        }
        {
          label = "preemption decision assertion";
          needle = "Decision::Preemption";
        }
      ];
    };
    "gate:app-random-branching" = {
      testFilter = "gate_app_random_branching_is_lazy_typed_and_bounded";
      result = "app_random=lazy-typed-site+bounded-seeded-samples+prefix-replacement+no-draw-equivalence";
      docNeedles = [
        {
          label = "app-random no-draw equivalence proof";
          needle = "A scenario without app-random draws produces no branches";
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
        {
          label = "validated app-random sample budget";
          needle = "pub struct AppRandomSampleBudget";
        }
        {
          label = "lazy app-random branch decisions";
          needle = "pub fn app_random_branch_decisions";
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
          needle = "gate_app_random_branching_is_lazy_typed_and_bounded";
        }
        {
          label = "app-random typed selection assertion";
          needle = "matches!(child.decision, Decision::Selection(_))";
        }
        {
          label = "app-random no-draw graph assertion";
          needle = "assert_eq!(before_count, graph.checkpoint_node_count())";
        }
      ];
    };
  };

  gateSpec =
    gateSpecs.${gateName}
    or (throw "guided/adaptive exploration check has no proof for ${gateName}");

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenFailuresFor = fileLabel: content: forbidden:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    forbidden;

  failures =
    failuresFor "docs/engineering/crucible/exploration.md" explorationPage gateSpec.docNeedles
    ++ failuresFor "crates/crucible/crucible-engine/src/model.rs" temporalGraph gateSpec.modelNeedles
    ++ failuresFor "crates/crucible/crucible-engine/src/lib.rs" libRs gateSpec.libNeedles
    ++ failuresFor "crates/crucible/crucible-engine/tests/gate_guided_adaptive_exploration.rs" guidedTest gateSpec.testNeedles
    ++ failuresFor "crates/crucible/crucible-test-support/tests/support/harness_lint/guidance.rs" guidanceLintTest (gateSpec.harnessNeedles or [])
    ++ forbiddenFailuresFor "crates/crucible/crucible-engine/tests/gate_guided_adaptive_exploration.rs" guidedTest [
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

      runtimeDeps = [pkgs.sqlite];

      buildDeps = [
        pkgs.sqlite
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
              -p crucible-engine \
              --test gate_guided_adaptive_exploration \
              ${gateSpec.testFilter} \
              -- --test-threads=1
            ${lib.optionalString (gateName == "gate:guidance-determinism-lint") ''
              cargo test \
                --frozen \
                --offline \
                --target-dir "$TMPDIR/crucible-guided-adaptive-exploration-target" \
                --manifest-path crates/Cargo.toml \
                -p crucible-test-support \
                --test harness_lint \
                guidance \
                -- --test-threads=1
            ''}
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
            gate=${gateName}
            ${gateSpec.result}
            RESULT
          '';
        }
      ];
    }
