{
  pkgs,
  attrPath ? "checks.crucible.phase9.gates.campaignDogfoodContract",
  taskIds ? ["T-CAM-0.5" "T-CAM-7.7" "T-CAM-9.7"],
  dependencies ? [],
}: let
  contractPath = ../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml;
  contract = builtins.fromTOML (builtins.readFile contractPath);
  requiredOperations = [
    "start"
    "status"
    "watch"
    "steer"
    "pause"
    "archive-transfer"
    "restart"
    "resume"
    "finding-export"
    "replay"
    "handoff"
    "stop"
    "cleanup"
  ];
  missingOperations =
    builtins.filter (
      operation: !(builtins.elem operation contract.command_journal.required_operations)
    )
    requiredOperations;
  valid =
    contract.schema
    == "aos.crucible.campaign-dogfood-contract.v2"
    && contract.gate == "gate:campaign-dogfood"
    && contract.acceptance_state == "manual-evidence-required"
    && contract.actual_product_workload_required
    && contract.public_surfaces_only
    && contract.independent_handoff_required
    && contract.minimum_duration_hours >= 24
    && contract.release_candidate_duration_hours >= 72
    && contract.command_journal.required
    && contract.command_journal.records_exit_status
    && contract.command_journal.records_structured_output
    && contract.command_journal.redacts_secrets
    && missingOperations == []
    && contract.scale.required
    && !(contract.scale ? minimum_executions)
    && contract.scale.minimum_hot_children >= 10000
    && contract.scale.minimum_promoted_template_generations >= 3
    && contract.scale.minimum_admitted_attempts >= 1000000
    && contract.scale.exercises_backpressure
    && contract.scale.exercises_resource_pressure
    && contract.resource_audit.required
    && !contract.resource_audit.unexplained_live_resources_permitted
    && contract.sign_offs.required_roles == ["driver" "independent_reviewer" "release_owner"]
    && contract.sign_offs.unsigned_result == "blocked"
    && contract.acceptance.accepted_result == "pass"
    && !contract.acceptance.unexplained_workaround_permitted
    && !contract.acceptance.hidden_repair_permitted;
in
  if !valid
  then throw "campaign dogfood manual evidence contract is incomplete"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-dogfood-contract";
      version = "0";
      src = contractPath;
      buildDeps = [pkgs.coreutils] ++ dependencies;

      phases = [
        {
          name = "validate-contract";
          script = ''
            set -eu
            test -s "$src"
            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            CONTRACT_VALIDATED
            check=${attrPath}
            gate=gate:campaign-dogfood
            tasks=${builtins.concatStringsSep "," taskIds}
            minimum_duration_hours=24
            release_candidate_duration_hours=72
            minimum_hot_children=10000
            minimum_promoted_template_generations=3
            minimum_admitted_attempts=1000000
            manual_evidence=required
            acceptance=not-evaluated
            RESULT
          '';
        }
      ];
    }
