{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.executionDecisionTaxonomy",
  taskIds ? ["T-EXEC-2"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  canonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  decision = builtins.readFile ../../crates/crucible/src/decision.rs;
  crateRoot = builtins.readFile ../../crates/crucible/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "closed decision enum";
        needle = "pub enum Decision";
      }
      {
        label = "delivery-order decision variant";
        needle = "DeliveryOrder(DeliveryOrderDecision)";
      }
      {
        label = "fault decision variant";
        needle = "FaultFires(FaultDecision)";
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
        label = "app-random decision variant";
        needle = "AppRandom(AppRandomDecision)";
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
    ++ failuresFor "crates/crucible/src/model/canonical.rs" canonical [
      {
        label = "decision canonicalization match";
        needle = "fn write_decision(hasher: &mut MaterialHasher, decision: &Decision)";
      }
      {
        label = "delivery-order canonical arm";
        needle = "Decision::DeliveryOrder(order)";
      }
      {
        label = "fault canonical arm";
        needle = "Decision::FaultFires(fault)";
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
        label = "app-random canonical arm";
        needle = "Decision::AppRandom(random)";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model/canonical.rs" canonical [
      {
        label = "wildcard decision canonicalization arm";
        needle = "_ =>";
      }
    ]
    ++ failuresFor "crates/crucible/src/decision.rs" decision [
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
        needle = "Decision::RngDraw(RngDecision { stream, value })";
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
    ++ failuresFor "crates/crucible/src/lib.rs" crateRoot [
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
    pkgs.mkDerivation {
      pname = "crucible-phase1-execution-decision-taxonomy";
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
          name = "run-execution-decision-taxonomy";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-execution-decision-taxonomy-target" \
              -p crucible \
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
            decisions=DeliveryOrder,FaultFires,RngDraw,Override,Preemption,AppRandom
            schedule_api=prefix,appended
            rng_stream_isolation=unrelated-world-edits
            RESULT
          '';
        }
      ];
    }
