{
  pkgs,
  attrPath ? "checks.crucible.phase9.gates.campaignOperatorAcceptanceContract",
  taskIds ? ["T-CAM-0.5" "T-CAM-8.6" "T-CAM-9.7"],
  dependencies ? [],
}: let
  contractPath = ../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-acceptance-contract.toml;
  contract = builtins.fromTOML (builtins.readFile contractPath);
  requiredOperations = [
    "fixture"
    "validate"
    "create"
    "start"
    "status"
    "watch"
    "steer"
    "branch"
    "derive"
    "pause"
    "resume"
    "stop"
    "finding-export"
    "replay"
    "cleanup"
  ];
  missingOperations =
    builtins.filter (
      operation: !(builtins.elem operation contract.command_journal.required_operations)
    )
    requiredOperations;
  requiredSignerRoles = [
    "driver"
    "independent_reviewer"
    "campaign_model_owner"
    "qemu_boundary_owner"
    "storage_owner"
    "guest_api_owner"
    "operations_owner"
  ];
  valid =
    contract.schema
    == "aos.crucible.campaign-operator-acceptance-contract.v1"
    && contract.gate == "gate:campaign-operator-acceptance"
    && contract.acceptance_state == "manual-evidence-required"
    && contract.actual_product_workload_required
    && contract.public_surfaces_only
    && contract.independent_driver_and_reviewer_required
    && contract.command_journal.required
    && contract.command_journal.records_exit_status
    && contract.command_journal.records_structured_output
    && contract.command_journal.redacts_secrets
    && missingOperations == []
    && contract.sign_offs.required_roles == requiredSignerRoles
    && contract.sign_offs.unsigned_result == "blocked"
    && contract.acceptance.accepted_result == "pass"
    && !contract.acceptance.unexplained_workaround_permitted
    && !contract.acceptance.hidden_repair_permitted;
in
  if !valid
  then throw "campaign operator acceptance manual evidence contract is incomplete"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase9-campaign-operator-acceptance-contract";
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
            gate=gate:campaign-operator-acceptance
            tasks=${builtins.concatStringsSep "," taskIds}
            public_surfaces_only=true
            independent_driver_and_reviewer_required=true
            manual_evidence=required
            acceptance=not-evaluated
            RESULT
          '';
        }
      ];
    }
