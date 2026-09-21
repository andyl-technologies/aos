{
  lib,
  kind,
  contractPath,
  releaseAcceptanceContractPath,
}: let
  contract = builtins.fromTOML (builtins.readFile contractPath);
  line = fields: lib.concatStringsSep "\t" fields;
  field = name: value: line ["field" name (toString value)];
  booleanField = name: value:
    field name (
      if value
      then "true"
      else "false"
    );
  present = name: line ["present" name];
  minimum = name: value: line ["minimum" name (toString value)];
  maximum = name: value: line ["maximum" name (toString value)];
  different = first: second: line ["different" first second];
  rows = rowKind: values: map (value: line [rowKind value]) values;
  common = [
    (line ["schema" "aos.crucible.campaign-manual-evidence-spec.v1"])
    (line ["gate" contract.gate])
    (line ["contract_sha256" (builtins.hashFile "sha256" contractPath)])
    (line ["release_acceptance_contract_sha256" (builtins.hashFile "sha256" releaseAcceptanceContractPath)])
    (present "release_manifest_env_sha256")
    (present "release_manifest_json_sha256")
  ];
  provenance = rows "present" contract.provenance.fields;
  operations = rows "operation" (contract.command_journal.required_operations or []);
  artifacts = rows "artifact" (contract.artifacts.items or []);
  resources = rows "resource" (contract.resource_audit.resources or []);
  injections = rows "injection" (map (injection: injection.id) (contract.injections or []));
  injectionBackends = map (
    injection: line ["injection_backend" injection.id injection.backend_scope]
  ) (contract.injections or []);
  forbidden = rows "forbidden_operation" (contract.forbidden_recovery.operations or []);
  signerRoles = rows "signer_role" contract.sign_offs.required_roles;
  operatorRequirements = [
    (booleanField "actual_product_workload" contract.actual_product_workload_required)
    (booleanField "public_surfaces_only" contract.public_surfaces_only)
    (booleanField "independent_driver_and_reviewer" contract.independent_driver_and_reviewer_required)
    (booleanField "unexplained_workarounds" contract.acceptance.unexplained_workaround_permitted)
    (booleanField "hidden_repairs" contract.acceptance.hidden_repair_permitted)
    (booleanField "resource_audit_complete" true)
    (minimum "duration_hours" contract.minimum_duration_hours)
    (maximum "duration_hours" contract.maximum_duration_hours)
  ];
  destructiveArtifacts = [
    "runbook"
    "campaign-snapshots"
    "exact-reproduction"
    "thin-reproduction"
    "telemetry"
    "resource-audit"
    "defect-list"
    "signed-result"
  ];
  destructiveRequirements = [
    (booleanField "constrained_host" contract.constrained_host_required)
    (booleanField "actual_product_workload" contract.actual_product_workload_required)
    (booleanField "independent_driver_and_reviewer" contract.independent_driver_and_reviewer_required)
    (booleanField "every_targeted_backend" contract.every_targeted_backend_required)
    (booleanField "authenticated_prior_state" contract.authenticated_prior_state_required)
    (booleanField "unexplained_live_resources" contract.unexplained_live_resources_permitted)
    (booleanField "forbidden_recovery_used" false)
    (booleanField "resource_audit_complete" contract.resource_audit.required)
  ];
  dogfoodRequirements = [
    (booleanField "actual_product_workload" contract.actual_product_workload_required)
    (booleanField "public_surfaces_only" contract.public_surfaces_only)
    (booleanField "independent_handoff" contract.independent_handoff_required)
    (booleanField "backpressure_exercised" contract.scale.exercises_backpressure)
    (booleanField "resource_pressure_exercised" contract.scale.exercises_resource_pressure)
    (booleanField "policy_revision_exercised" contract.scale.exercises_policy_revision)
    (booleanField "unexplained_live_resources" contract.resource_audit.unexplained_live_resources_permitted)
    (booleanField "unexplained_workarounds" contract.acceptance.unexplained_workaround_permitted)
    (booleanField "hidden_repairs" contract.acceptance.hidden_repair_permitted)
    (booleanField "resource_audit_complete" contract.resource_audit.required)
    (minimum "duration_hours" contract.minimum_duration_hours)
    (minimum "duration_hours" contract.release_candidate_duration_hours)
    (minimum "hot_children_created_and_retired" contract.scale.minimum_hot_children)
    (minimum "promoted_template_generations_reached" contract.scale.minimum_promoted_template_generations)
    (minimum "admitted_lightweight_attempts" contract.scale.minimum_admitted_attempts)
  ];
  e2eRequirements = [
    (booleanField "physical_cross_host_reproduction" contract.physical_cross_host_required)
    (booleanField "live_packaged_qemu" contract.live_packaged_qemu_required)
    (booleanField "tcg_only" contract.tcg_only)
    (booleanField "exact_closure_match" contract.provenance.exact_closure_match_required)
    (booleanField "distinct_physical_host_attestations" contract.provenance.distinct_physical_host_attestations_required)
    (booleanField "randomized_worker_scheduling" contract.matrix.randomized_worker_scheduling)
    (booleanField "wall_clock_jitter" contract.matrix.wall_clock_jitter)
    (booleanField "host_io_stall" contract.matrix.host_io_stall)
    (booleanField "bounded_scheduler_preemption" contract.matrix.bounded_scheduler_preemption)
    (booleanField "byte_identical_reproduction_artifact" contract.artifacts.byte_identical_reproduction_artifact_required)
    (booleanField "byte_identical_canonical_results" contract.artifacts.byte_identical_canonical_results_required)
    (booleanField "retry_to_obtain_pass" contract.acceptance.retry_to_obtain_pass_permitted)
    (field "varied_core_counts" (lib.concatMapStringsSep "," toString contract.varied_core_counts))
    (field "hostile_profiles" (lib.concatStringsSep "," contract.hostile_profiles))
    (minimum "physical_host_count" contract.minimum_distinct_physical_hosts)
    (present "producer_physical_host_id")
    (present "reproducer_physical_host_id")
    (different "producer_physical_host_id" "reproducer_physical_host_id")
  ];
  requirements =
    if kind == "operator"
    then operatorRequirements
    else if kind == "destructive-recovery"
    then destructiveRequirements ++ rows "artifact" destructiveArtifacts
    else if kind == "dogfood"
    then dogfoodRequirements
    else if kind == "e2e-determinism"
    then e2eRequirements
    else throw "unsupported campaign manual evidence kind: ${kind}";
in
  builtins.toFile "crucible-campaign-${kind}-manual-evidence-spec.tsv" (
    lib.concatStringsSep "\n" (
      common
      ++ requirements
      ++ provenance
      ++ operations
      ++ artifacts
      ++ resources
      ++ injections
      ++ injectionBackends
      ++ forbidden
      ++ signerRoles
    )
    + "\n"
  )
