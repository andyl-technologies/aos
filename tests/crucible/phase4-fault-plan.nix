{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultPlan",
  taskIds ? ["T-FAULT-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  faultTest = builtins.readFile ../../crates/crucible/tests/fault_plan.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-10 completion note";
        needle = "Completed by `checks.crucible.phase4.faultPlan`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "FaultPlan public type";
        needle = "pub struct FaultPlan";
      }
      {
        label = "FaultPlan entry enum";
        needle = "pub enum FaultPlanEntry";
      }
      {
        label = "Plan carries FaultPlan";
        needle = "PlanKind::FaultPlan";
      }
      {
        label = "FaultPlan constructor validates world";
        needle = "pub fn from_fault_plan_for_world";
      }
      {
        label = "full taxonomy wrapper in InjectFault path";
        needle = "MembershipFault::Taxonomy";
      }
      {
        label = "declared link-id validation";
        needle = "PlanFaultUnknownLinkId";
      }
      {
        label = "device refs fail closed until world declares devices";
        needle = "PlanFaultUnknownDevice";
      }
      {
        label = "auto-heal overflow validation";
        needle = "PlanFaultDurationOverflow";
      }
      {
        label = "fault-plan TOML rows";
        needle = "fault_entry";
      }
      {
        label = "fault-plan binary sentinel";
        needle = "FAULT_PLAN_BINARY_SENTINEL";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "fault-plan pure At lowering";
        needle = "fn lower_fault_plan_actions";
      }
      {
        label = "taxonomy action lowering";
        needle = "MembershipFault::taxonomy";
      }
      {
        label = "taxonomy action validation";
        needle = "fn validate_taxonomy_fault_reference";
      }
      {
        label = "canonical evaluation times";
        needle = "fn fault_plan_action_evaluation_times";
      }
    ]
    ++ failuresFor "crates/crucible/src/scheduler Rust source tree" (import ./_crucible-scheduler-source.nix {inherit lib;}) [
      {
        label = "taxonomy fault state";
        needle = "active_taxonomy_faults";
      }
      {
        label = "combined active taxonomy faults";
        needle = "pub fn combined_faults(&self) -> CombinedFaults";
      }
      {
        label = "trigger-owned network fault bridge";
        needle = "pub fn apply_trigger_network_faults_to_link";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_plan.rs" faultTest [
      {
        label = "canonicalization and lowering test";
        needle = "fault_plan_canonicalizes_and_lowers_to_pure_at_fault_events";
      }
      {
        label = "same-time total order test";
        needle = "fault_plan_same_time_heal_fires_after_inject";
      }
      {
        label = "validation test";
        needle = "fault_plan_rejects_undeclared_or_unordered_references";
      }
      {
        label = "trigger combined-fault state test";
        needle = "lowered_fault_plan_updates_trigger_combined_faults";
      }
      {
        label = "trigger live network loss bridge test";
        needle = "lowered_network_loss_fault_plan_applies_to_live_netlink";
      }
      {
        label = "trigger live network latency bridge test";
        needle = "lowered_network_latency_fault_plan_queues_link_recompute";
      }
      {
        label = "event-graph hash equivalence test";
        needle = "fault_plan_hash_matches_equivalent_pure_at_event_graph";
      }
      {
        label = "serialization round trip test";
        needle = "fault_plan_round_trips_through_canonical_toml_and_binary";
      }
      {
        label = "in-range TOML param test";
        needle = "fault_plan_toml_rejects_out_of_range_integer_params";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault plan import";
        needle = "faultPlan = import ./phase4-fault-plan.nix";
      }
      {
        label = "phase4 fault plan attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultPlan\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/fault_plan.rs" faultTest [
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
  then throw "crucible phase4 fault-plan check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-plan";
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
          name = "run-fault-plan";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-plan-target" \
              -p crucible \
              --test fault_plan \
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
            plan=fault-plan
            lowering=pure-at-inject-heal
            validation=declared-refs,heal-tags,integer-params
            RESULT
          '';
        }
      ];
    }
