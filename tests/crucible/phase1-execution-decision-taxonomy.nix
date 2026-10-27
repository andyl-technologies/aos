{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionDecisionTaxonomy",
  taskIds ? ["T-EXEC-2"],
}: let
  inherit (import ./_test-gate.nix {inherit pkgs lib;}) mkCrucibleTestGate;

  model = import ./_crucible-model-source.nix {inherit lib;};
  canonical = builtins.readFile ../../crates/crucible/crucible-engine/src/model/canonical.rs;
  decision = builtins.readFile ../../crates/crucible/crucible-engine/src/decision.rs;
  crateRoot = import ./_crucible-tests-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "crates/crucible/crucible-engine/src/model.rs" model [
      {
        label = "closed decision enum";
        needle = "pub enum Decision";
      }
      {
        label = "delivery-order decision variant";
        needle = "DeliveryOrder(DeliveryOrderDecision)";
      }
      {
        label = "RNG draw decision variant";
        needle = "RngDraw(RngDecision)";
      }
      {
        label = "override decision variant";
        needle = "Override(OverrideDecision)";
      }
      {
        label = "preemption decision variant";
        needle = "Preemption(PreemptionDecision)";
      }
      {
        label = "selection decision variant";
        needle = "Selection(SelectionDecision)";
      }
      {
        label = "schedule type";
        needle = "pub struct Schedule";
      }
      {
        label = "schedule prefix API";
        needle = "pub fn prefix(&self, len: usize) -> Result<Self, ScheduleError>";
      }
      {
        label = "schedule appended API";
        needle = "pub fn appended(&self, decision: Decision) -> Self";
      }
      {
        label = "RNG draw records stream id";
        needle = "pub struct RngDecision";
      }
      {
        label = "RNG draw stream field";
        needle = "pub stream: RngStreamId";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/model/canonical.rs" canonical [
      {
        label = "decision canonicalization match";
        needle = "fn write_decision(hasher: &mut MaterialHasher, decision: &Decision)";
      }
      {
        label = "delivery-order canonical arm";
        needle = "Decision::DeliveryOrder(order)";
      }
      {
        label = "RNG draw canonical arm";
        needle = "Decision::RngDraw(draw)";
      }
      {
        label = "override canonical arm";
        needle = "Decision::Override(override_decision)";
      }
      {
        label = "preemption canonical arm";
        needle = "Decision::Preemption(preemption)";
      }
      {
        label = "selection canonical arm";
        needle = "Decision::Selection(selection)";
      }
    ]
    ++ forbiddenFor "crates/crucible/crucible-engine/src/model/canonical.rs" canonical [
      {
        label = "wildcard decision canonicalization arm";
        needle = "_ =>";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/decision.rs" decision [
      {
        label = "decision recorder type";
        needle = "pub struct DecisionRecorder";
      }
      {
        label = "per-stream fork cache";
        needle = "streams: BTreeMap<RngStreamId, DecisionStream>";
      }
      {
        label = "name-hash fork path";
        needle = ".or_insert_with(|| self.rng.fork_in_domain(&stream.domain, &stream.name))";
      }
      {
        label = "existing schedule hydration";
        needle = "hydrate_streams(&rng, configuration.schedule.decisions())";
      }
      {
        label = "raw RNG draw recording";
        needle = "Decision::RngDraw(RngDecision::ordinal(";
      }
      {
        label = "unrelated world edit stream isolation test";
        needle = "decision_recorder_does_not_perturb_streams_for_unrelated_world_edits";
      }
      {
        label = "scenario material edit fixture";
        needle = "world.nodes=node-a,node-z";
      }
      {
        label = "stable stream assertion";
        needle = "assert_eq!(baseline_draw, edited_draw);";
      }
      {
        label = "schedule recording assertion";
        needle = "edited.schedule().decisions().get(1)";
      }
    ]
    ++ failuresFor "crates/crucible/crucible-engine/src/lib.rs" crateRoot [
      {
        label = "schedule prefix test";
        needle = "schedule_prefix_bounds_are_checked";
      }
      {
        label = "append does not mutate parent test";
        needle = "step_appends_decision_without_mutating_parent";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes execution decision taxonomy check";
        needle = "executionDecisionTaxonomy = import ./phase1-execution-decision-taxonomy.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 execution decision taxonomy check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    mkCrucibleTestGate {
      pname = "crucible-phase1-execution-decision-taxonomy";

      buildDeps = [
        pkgs.coreutils
        pkgs.sed
        pkgs.sqlite
      ];

      phases = [
        {
          name = "run-execution-decision-taxonomy";
          script = ''
            set -eu
            cd crates
            crucible-cargo test \
              -p crucible-engine \
              --lib \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            decisions=DeliveryOrder,RngDraw,Override,Preemption,Selection
            fault_outcomes=ResolvedEffectTrace
            schedule_api=prefix,appended
            rng_stream_isolation=unrelated-world-edits
            RESULT
          '';
        }
      ];
    }
