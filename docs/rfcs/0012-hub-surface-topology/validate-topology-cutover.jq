def error_record($code; $path): {code: $code, path: $path};
def require($condition; $code; $path):
  if $condition then [] else [error_record($code; $path)] end;

def values($items; $field): [$items[]? | .[$field]] | sort;
def unique_values($items; $field): values($items; $field) | unique;
def same_unique_values($left; $right; $field):
  values($left; $field) == unique_values($left; $field)
  and values($right; $field) == unique_values($right; $field)
  and values($left; $field) == values($right; $field);
def contains_id($items; $field; $value): any($items[]?; .[$field] == $value);
def ref_node_id($reference): $reference.artifact_node_id;
def canonical_json_text:
  walk(if type == "object" then to_entries | sort_by(.key) | from_entries else . end)
  | tojson;
def base64url:
  @base64 | gsub("\\+"; "-") | gsub("/"; "_") | gsub("=+$"; "");
def domain_digest_marker($domain; $value):
  "derive:domain-sha256:\($domain | base64url):\($value | canonical_json_text | base64url)";
def instant_key:
  capture("^(?<year>[0-9]{4})-(?<month>[0-9]{2})-(?<day>[0-9]{2})T(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})(?:\\.(?<fraction>[0-9]+))?Z$")
  | [(.year|tonumber),(.month|tonumber),(.day|tonumber),(.hour|tonumber),
     (.minute|tonumber),(.second|tonumber),
     ((.fraction // "") + "000000000" | .[0:9] | tonumber)];

def typed_resources($plan):
  ([ $plan.topology.instances[]? | {kind:"instance", stable_id} ]
   + [ $plan.topology.organizations[]? | {kind:"organization", stable_id} ]
   + [ $plan.topology.projects[]? | {kind:"project", stable_id} ]
   + [ $plan.topology.surfaces[]? | {kind:.kind, stable_id} ]
   + [ $plan.topology.bindings[]? | {kind:"storage_binding", stable_id} ]
   + [ $plan.topology.binding_capability_observations[]? | {kind:"binding_capability_observation", stable_id} ]
   + [ $plan.topology.credential_generations[]? | {kind:"credential_generation", stable_id} ]
   + [ $plan.topology.binding_write_revisions[]? | {kind:"binding_write_revision", stable_id} ]
   + [ $plan.topology.binding_grants[]? | {kind:"binding_grant", stable_id} ]
   + [ $plan.topology.storage_defaults[]? | {kind:"storage_default", stable_id} ]
   + [ $plan.topology.placements[]? | {kind:"placement", stable_id} ]
   + [ $plan.topology.write_authorities[]? | {kind:"write_authority", stable_id} ]
   + [ $plan.topology.delivery_endpoints[]? | {kind:"delivery_endpoint", stable_id} ]
   + [ $plan.topology.domains[]? | {kind:"domain", stable_id} ]
   + [ $plan.topology.network_boundaries[]? | {kind:"network_boundary", stable_id} ]
   + [ $plan.topology.gateways[]? | {kind:"storage_gateway", stable_id} ]
   + [ $plan.topology.routes[]? | {kind:"delivery_route", stable_id} ]
   + [ $plan.topology.route_configurations[]? | {kind:"route_configuration", stable_id} ]
   + [ $plan.topology.placement_policies[]? | {kind:"placement_policy", stable_id} ]
   + [ $plan.topology.equivalence_sets[]? | {kind:"equivalence_set", stable_id} ]
   + [ $plan.topology.registry_publications[]? | {kind:"registry_publication", stable_id} ]
   + [ $plan.topology.publication_bindings[]? | {kind:"publication_binding", stable_id} ]
   + [ $plan.topology.population_targets[]? | {kind:"population_target", stable_id} ]
   + [ $plan.topology.retention_subscriptions[]? | {kind:"retention_subscription", stable_id} ]
   + [ $plan.topology.inventories[]? | {kind:"inventory_generation", stable_id} ]
   + [ $plan.topology.placement_manifests[]? | {kind:"placement_manifest", stable_id} ])
  | sort_by(.kind, .stable_id);

def target_pairs($plan):
  typed_resources($plan) | map("\(.kind)\u0000\(.stable_id)");
def edge_target_pairs($plan):
  [$plan.topology.mapping_edges[]?
   | "\(.target_resource_kind)\u0000\(.target_stable_id)"] | sort;

def mapping_contract_valid($plan):
  (typed_resources($plan)) as $targets
  | ($plan.source.resource_nodes) as $nodes
  | ($plan.topology.mapping_edges) as $edges
  | ([ $plan.topology.instances[].stable_id,
       $plan.topology.organizations[].stable_id,
       $plan.topology.projects[].stable_id ]) as $owners
  | (values($nodes; "node_id") == unique_values($nodes; "node_id"))
  and (values($edges; "edge_id") == unique_values($edges; "edge_id"))
  and (edge_target_pairs($plan) == (edge_target_pairs($plan) | unique))
  and (edge_target_pairs($plan) == target_pairs($plan))
  and ([ $edges[] as $edge
         | ([$nodes[] | select(.node_id == $edge.source_node_id)] | .[0]) as $source
         | $source != null
           and $edge.owner_scope_stable_id == $source.owner_scope_stable_id
           and ($owners | index($edge.owner_scope_stable_id) != null)
           and ($targets | any(.kind == $edge.target_resource_kind
                               and .stable_id == $edge.target_stable_id))
           and $edge.evidence_required ] | all)
  and ([ $nodes[] as $node
         | ([$edges[] | select(.source_node_id == $node.node_id)]
             | sort_by(.ordinal)) as $outgoing
         | ($outgoing | length) == $node.expected_mapping_edge_count
           and [$outgoing[].ordinal] == [range(1; ($outgoing | length) + 1)] ] | all)
  and ([ $nodes[] | select(.expected_mapping_edge_count > 1) ] | length) > 0
  and $plan.topology.mapping_coverage.source_count == ($nodes | length)
  and $plan.topology.mapping_coverage.mapping_count == ($edges | length)
  and $plan.topology.mapping_coverage.target_count == ($targets | length)
  and $plan.topology.mapping_coverage.missing_source_count == 0
  and $plan.topology.mapping_coverage.unmapped_target_count == 0
  and $plan.topology.mapping_coverage.duplicate_source_count == 0
  and $plan.topology.mapping_coverage.duplicate_target_count == 0;

def exact_route_configuration($plan; $route):
  [$plan.topology.route_configurations[]
   | select(.stable_id == $route.configuration_generation_stable_id
            and .owner_stable_id == $route.stable_id
            and .state == "active"
            and .access_policy == $route.access_policy
            and .configuration_digest == $route.configuration_digest)] | length == 1;

def reference_contract_valid($plan):
  ($plan.topology.instances) as $instances
  | ($plan.topology.organizations) as $orgs
  | ($plan.topology.projects) as $projects
  | ($plan.topology.surfaces) as $surfaces
  | ([$surfaces[] | select(.kind == "registry")]) as $registries
  | ([$surfaces[] | select(.kind == "binary_cache")]) as $caches
  | ($plan.topology.bindings) as $bindings
  | ($plan.topology.placements) as $placements
  | ($plan.topology.routes) as $routes
  | ([ $instances[].stable_id, $orgs[].stable_id, $projects[].stable_id ]) as $owners
  | ([ $orgs[] | contains_id($instances; "stable_id"; .owner_stable_id) ] | all)
  and ([ $projects[] | contains_id($orgs; "stable_id"; .owner_stable_id) ] | all)
  and ([ $surfaces[] as $surface | $owners | index($surface.owner_scope_stable_id) != null ] | all)
  and ([ $bindings[] as $binding
         | ($owners | index($binding.owner_scope_stable_id) != null)
           and ([$plan.topology.binding_capability_observations[]
                 | select(.owner_stable_id == $binding.stable_id
                          and .generation == $binding.capabilities.observation_generation
                          and .state == "observed")] | length) == 1
           and ([$plan.topology.binding_write_revisions[]
                 | select(.owner_stable_id == $binding.stable_id
                          and .generation == $binding.current_write_revision
                          and .state == "active")] | length) == 1
           and ([ $binding.credential_refs[]? as $reference
                 | [$plan.topology.credential_generations[]
                    | select(.stable_id == $reference.stable_id
                             and .owner_stable_id == $binding.stable_id
                             and .purpose == $reference.purpose
                             and .version == $reference.version
                             and .metadata_digest == $reference.metadata_digest)] | length == 1 ] | all) ] | all)
  and ([ $plan.topology.binding_grants[] as $grant
         | contains_id($bindings; "stable_id"; $grant.source_stable_id)
           and ($owners | index($grant.target_stable_id) != null) ] | all)
  and ([ $plan.topology.storage_defaults[] as $default
         | ($owners | index($default.source_stable_id) != null)
           and contains_id($bindings; "stable_id"; $default.target_stable_id) ] | all)
  and ([ $placements[] as $placement
         | contains_id($bindings; "stable_id"; $placement.binding_stable_id)
           and ($surfaces | any(.stable_id == $placement.surface.stable_id
                                and .kind == $placement.surface.kind)) ] | all)
  and ([ $plan.topology.write_authorities[] as $authority
         | ([$placements[] | select(.stable_id == $authority.desired_placement_stable_id)] | .[0]) as $desired
         | ([$placements[] | select(.stable_id == $authority.observed_placement_stable_id)] | .[0]) as $observed
         | ([$plan.topology.binding_write_revisions[]
             | select(.stable_id == $authority.binding_write_revision_stable_id)] | .[0]) as $revision
         | $desired != null and $observed != null and $revision != null
           and $desired.surface.stable_id == $authority.surface_stable_id
           and $observed.surface.stable_id == $authority.surface_stable_id
           and $desired.binding_stable_id == $revision.owner_stable_id
           and $observed.binding_stable_id == $revision.owner_stable_id
           and $revision.generation == $authority.generation
           and $revision.state == "active" ] | all)
  and ([ $routes[] as $route
         | ($surfaces | any(.stable_id == $route.surface.stable_id and .kind == $route.surface.kind))
           and exact_route_configuration($plan; $route)
           and ($plan.topology.delivery_endpoints | any(.stable_id == $route.endpoint_generation_stable_id))
           and ($plan.topology.network_boundaries | any(.stable_id == $route.boundary_generation_stable_id))
           and ($route.gateway_generation_stable_id == null
                or ($plan.topology.gateways | any(.stable_id == $route.gateway_generation_stable_id)))
           and ($plan.topology.placement_policies
                | any(.stable_id == $route.placement_policy_generation_stable_id
                      and .owner_stable_id == $route.surface.stable_id and .state == "active"))
           and ([ $route.backend_placement_stable_ids[] as $placement_id
                  | $placements | any(.stable_id == $placement_id
                                      and .surface.stable_id == $route.surface.stable_id)] | all) ] | all)
  and ([ $plan.topology.route_configurations[] as $configuration
         | [$routes[] | select(.configuration_generation_stable_id == $configuration.stable_id)] | length == 1 ] | all)
  and ([ $plan.topology.domains[] as $domain
         | $routes | any(.stable_id == $domain.route_stable_id
                         and .access_policy == $domain.access_policy) ] | all)
  and ([ $plan.topology.registry_publications[]
         | contains_id($registries; "stable_id"; .owner_stable_id) ] | all)
  and ([ ($plan.topology.publication_bindings + $plan.topology.population_targets)[]
         | contains_id($registries; "stable_id"; .source_stable_id)
           and contains_id($caches; "stable_id"; .target_stable_id) ] | all)
  and ([ $plan.topology.retention_subscriptions[] as $retention
         | contains_id($caches; "stable_id"; $retention.cache_stable_id)
           and contains_id($registries; "stable_id"; $retention.registry_stable_id)
           and ($plan.topology.registry_publications
                | any(.stable_id == $retention.source_generation_stable_id
                      and .owner_stable_id == $retention.registry_stable_id)) ] | all)
  and ([ $plan.topology.inventories[] as $inventory
         | contains_id($caches; "stable_id"; $inventory.cache_stable_id)
           and ([ $inventory.placement_manifests[] as $manifest
                  | ($plan.topology.placement_manifests | any(.stable_id == $manifest.manifest_stable_id))
                    and ($placements | any(.stable_id == $manifest.placement_stable_id
                                          and .surface.kind == "binary_cache"
                                          and .surface.stable_id == $inventory.cache_stable_id))
                    and $manifest.strong_identity_count == $manifest.object_count ] | all) ] | all);

def planned_checks($plan):
  ($plan.validation.required_checks
   + [$plan.switch.new_runtime_health_gate, $plan.switch.old_runtime_stop_gate]
   + $plan.gc_gate.enablement_requires
   + [$plan.rollback.write_reopen_gate, $plan.legacy_removal.repository_guard])
  | unique_by(.check_id);
def reported_checks($report): $report.preflight.online_checks + $report.validation.checks;

def check_contract_valid($plan; $report):
  (planned_checks($plan)) as $planned
  | (reported_checks($report)) as $reported
  | same_unique_values($planned; $reported; "check_id")
  and ([ $planned[] as $expected
         | [$reported[] | select(.check_id == $expected.check_id)] as $actual
         | ($actual | length) == 1
           and $actual[0].kind == $expected.kind
           and $actual[0].evidence_required == $expected.evidence_required
           and ref_node_id($actual[0].evidence) != null ] | all);

def blocker_contract_valid($plan; $report):
  same_unique_values($plan.blockers; $report.blockers; "blocker_id")
  and ([ $plan.blockers[] as $expected
         | [$report.blockers[] | select(.blocker_id == $expected.blocker_id)] as $actual
         | [reported_checks($report)[]
            | select(.check_id == $expected.resolution_check_id)] as $checks
         | ($actual | length) == 1
           and ([typed_resources($plan)[]
                 | select(.kind == $expected.resource.kind
                          and .stable_id == $expected.resource.stable_id)] | length) == 1
           and $actual[0].code == $expected.code
           and $actual[0].resource == $expected.resource
           and $actual[0].resolution_check_id == $expected.resolution_check_id
           and $actual[0].state == "resolved"
           and ($checks | length) == 1
           and $checks[0].result == "pass"
           and ref_node_id($actual[0].resolution_evidence) == ref_node_id($checks[0].evidence) ] | all);

def smoke_contract_valid($plan; $report):
  same_unique_values($plan.smoke_tests; $report.smoke_tests; "test_id")
  and ([ $plan.smoke_tests[] as $expected
         | [$report.smoke_tests[] | select(.test_id == $expected.test_id)] as $actual
         | ($actual | length) == 1
           and $actual[0].surface == $expected.surface
           and $actual[0].route_stable_id == $expected.route_stable_id
           and $actual[0].placement_stable_id == $expected.placement_stable_id
           and $actual[0].binding_stable_id == $expected.binding_stable_id
           and $actual[0].method == $expected.method
           and $actual[0].path_digest == $expected.path_digest
           and $actual[0].auth_context == $expected.auth_context
           and $actual[0].evidence_required == $expected.evidence_required
           and ($actual[0].response_digest | type) == "string"
           and ($actual[0].status | type) == "number"
           and (if $actual[0].result == "pass"
                then $actual[0].status == $expected.expected_status
                else true end)
           and ref_node_id($actual[0].evidence) != null ] | all)
  and ([ $plan.topology.routes[] as $route
         | ([ $route.backend_placement_stable_ids[] as $placement_id
              | ($plan.topology.placements | map(select(.stable_id == $placement_id))[0]) as $placement
              | any($plan.smoke_tests[];
                    .route_stable_id == $route.stable_id
                    and .placement_stable_id == $placement_id
                    and .binding_stable_id == $placement.binding_stable_id
                    and .expected_status < 400) ] | all)
           and (if $route.access_policy == "public"
                then any($plan.smoke_tests[]; .route_stable_id == $route.stable_id
                         and .auth_context == "anonymous" and .expected_status < 400)
                else any($plan.smoke_tests[]; .route_stable_id == $route.stable_id
                         and .auth_context == "anonymous"
                         and (.expected_status == 401 or .expected_status == 403))
                  and any($plan.smoke_tests[]; .route_stable_id == $route.stable_id
                         and .auth_context != "anonymous" and .expected_status < 400)
                end) ] | all);

def attempt_contract_valid($plan; $report):
  ($report.attempt_history | sort_by(.ordinal)) as $history
  | (domain_digest_marker(
       "aos.hub.topology-cutover.idempotency/v1";
       {bundle_id:$plan.bundle_id,
        plan_id:$plan.plan_id,
        source_deployment_revision:$plan.source.deployment_revision,
        target_deployment_revision:$plan.target.deployment_revision,
        target_schema_revision:$plan.target.schema_revision})) as $expected_key
  | $report.attempt == $history[-1]
  and [$history[].ordinal] == [range(1; ($history | length) + 1)]
  and ([$history[].attempt_id] | length) == ([$history[].attempt_id] | unique | length)
  and $plan.execution_contract.idempotency_key == $expected_key
  and ([ range(0; $history | length) as $index
         | $history[$index].namespace == $plan.execution_contract.attempt_namespace
           and $history[$index].idempotency_key == $expected_key
           and (if $index == 0 then $history[$index].predecessor_attempt_id == null
                else $history[$index].predecessor_attempt_id == $history[$index - 1].attempt_id
                  and $history[$index].predecessor_attempt_id != $history[$index].attempt_id end)
           and (if $history[$index].state == "discarded"
                then $history[$index].discarded_at != null
                else $history[$index].discarded_at == null end) ] | all)
  and ($history | length) <= $plan.execution_contract.maximum_attempts;

def transition_contract_valid($plan; $report):
  ($report.transition_ledger | sort_by(.sequence)) as $ledger
  | $ledger == $report.transition_ledger
  and [$ledger[].sequence] == [range(1; ($ledger | length) + 1)]
  and $ledger[0].from_state == "planned"
  and ([ range(1; $ledger | length) as $index
         | $ledger[$index].from_state == $ledger[$index - 1].to_state ] | all)
  and ([$ledger[].occurred_at | instant_key] as $instants
       | [range(1; $instants|length) as $index
          | $instants[$index - 1] < $instants[$index]] | all)
  and ([$ledger[].admitted_target_write_count] | add) == 0
  and (if $report.result == "succeeded" then
        $report.attempt.state == "completed"
        and [$ledger[].to_state] == ["quiesced","backed_up","transformed","validated","switched","closed"]
        and [$ledger[].target_write_open_count] == [0,0,0,0,1,1]
      elif $report.result == "rolled_back" then
        $report.attempt.state == "rolled_back"
        and [$ledger[].to_state] == ["quiesced","backed_up","transformed","validated","switched","rolled_back"]
        and ([$ledger[].target_write_open_count] | add) == 0
      else
        $report.attempt.state == "failed_closed"
        and [$ledger[].to_state] == ["quiesced","backed_up","transformed","validated","failed_closed"]
        and ([$ledger[].target_write_open_count] | add) == 0
      end);

def database_contract_valid($plan; $report; $verification):
  (values($plan.source.databases; "stable_id") == unique_values($plan.source.databases; "stable_id"))
  and (values($plan.backup; "database_stable_id") == unique_values($plan.backup; "database_stable_id"))
  and (values($report.backup; "database_stable_id") == unique_values($report.backup; "database_stable_id"))
  and (values($report.rollback.database_restores; "database_stable_id") == unique_values($report.rollback.database_restores; "database_stable_id"))
  and (values($verification.database_restore_validation.proofs; "database_stable_id") == unique_values($verification.database_restore_validation.proofs; "database_stable_id"))
  and (values($plan.source.databases; "stable_id") == values($plan.backup; "database_stable_id"))
  and (values($plan.source.databases; "stable_id") == values($report.backup; "database_stable_id"))
  and (values($plan.source.databases; "stable_id") == values($report.rollback.database_restores; "database_stable_id"))
  and (values($plan.source.databases; "stable_id") == values($verification.database_restore_validation.proofs; "database_stable_id"))
  and $report.rollback.restore_expected_count == ($report.rollback.database_restores | length)
  and $report.rollback.restore_completed_count
      == ([$report.rollback.database_restores[] | select(.status == "pass")] | length)
  and $report.rollback.restore_failed_count
      == ([$report.rollback.database_restores[] | select(.status == "failed")] | length)
  and (if $report.rollback.restore_failed_count > 0 then
         $report.rollback.restore_set_result == "failed"
       elif $report.rollback.restore_completed_count == $report.rollback.restore_expected_count then
         $report.rollback.restore_set_result == "pass"
       else
         $report.rollback.restore_completed_count == 0
         and $report.rollback.restore_set_result == "not_run"
       end)
  and ([ $plan.source.databases[] as $database
         | ($plan.backup | map(select(.database_stable_id == $database.stable_id))[0]) as $planned
         | ($report.backup | map(select(.database_stable_id == $database.stable_id))[0]) as $backup
         | ($report.rollback.database_restores | map(select(.database_stable_id == $database.stable_id))[0]) as $restore
         | ($verification.database_restore_validation.proofs | map(select(.database_stable_id == $database.stable_id))[0]) as $proof
         | ([$plan.backup[] | select(.database_stable_id == $database.stable_id)] | length) == 1
           and ([$report.backup[] | select(.database_stable_id == $database.stable_id)] | length) == 1
           and ([$report.rollback.database_restores[] | select(.database_stable_id == $database.stable_id)] | length) == 1
           and ([$verification.database_restore_validation.proofs[] | select(.database_stable_id == $database.stable_id)] | length) == 1
           and $planned.database_kind == $database.kind
           and $backup.database_kind == $database.kind
           and $restore.database_kind == $database.kind
           and $planned.destination_artifact_node_id == $backup.artifact_node_id
           and $restore.backup_artifact_node_id == $backup.artifact_node_id
           and $restore.expected_source_digest == $backup.source_logical_digest
           and $restore.expected_source_row_count == $backup.restore_verification.row_count
           and $proof.backup_artifact_node_id == $backup.artifact_node_id
           and $proof.expected_source_digest == $restore.expected_source_digest
           and $proof.expected_source_row_count == $restore.expected_source_row_count
           and $proof.status == $restore.status
           and $proof.restored_digest == $restore.restored_digest
           and $proof.restored_row_count == $restore.restored_row_count
           and $proof.verification_query_set_node_id == $restore.verification_query_set_node_id
           and $proof.evidence_node_id == (ref_node_id($restore.evidence) // null)
           and (if $report.result == "rolled_back"
                then $restore.status == "pass"
                  and $restore.restored_digest == $restore.expected_source_digest
                  and $restore.restored_row_count == $restore.expected_source_row_count
                  and ref_node_id($restore.evidence) != null
                elif $report.result == "failed_closed"
                     and $report.rollback.state == "closed_failed"
                then ($restore.status == "pass" or $restore.status == "failed" or $restore.status == "not_run")
                  and (if $restore.status == "failed"
                       then $restore.restore_started_at != null
                         and $restore.restore_finished_at != null
                         and ref_node_id($restore.evidence) != null
                       else true end)
                else $restore.status == "not_run"
                  and $restore.restore_started_at == null and $restore.restore_finished_at == null
                  and $restore.restored_digest == null and $restore.restored_row_count == null
                  and $restore.evidence == null
                end) ] | all);

def do_aggregate_contract_valid($report; $verification):
  ([ $report.backup[] | select(.database_kind == "durable_object_sqlite")
     | . as $backup
     | ($backup.object_manifests | sort_by(canonical_json_text)) as $manifests
     | {database_stable_id,
        object_manifests:$manifests,
        recomputed_object_count:($manifests | length),
        recomputed_row_count:([$manifests[].row_count] | add),
        object_set_sha256:domain_digest_marker("aos.hub.topology-cutover.set/v1"; $manifests),
        aggregate_sha256:domain_digest_marker(
          "aos.hub.topology-cutover.do-aggregate/v1";
          {database_stable_id:$backup.database_stable_id,
           object_manifests:$manifests,
           recomputed_object_count:($manifests | length),
           recomputed_row_count:([$manifests[].row_count] | add)})} ]
     | sort_by(.database_stable_id)) as $expected
  | ([ $verification.durable_object_aggregates[]
       | {database_stable_id, object_manifests, recomputed_object_count,
          recomputed_row_count, object_set_sha256, aggregate_sha256} ]
     | sort_by(.database_stable_id)) == $expected
  and ([ $report.backup[] | select(.database_kind == "durable_object_sqlite")
         | . as $backup
         | ($backup.object_manifests | sort_by(canonical_json_text)) as $manifests
         | ($backup.observed_object_set_digest
            == domain_digest_marker("aos.hub.topology-cutover.set/v1"; $manifests))
           and ($backup.expected_object_set_digest == $backup.observed_object_set_digest)
           and ($backup.aggregate_manifest_digest
             == domain_digest_marker(
               "aos.hub.topology-cutover.do-aggregate/v1";
               {database_stable_id:$backup.database_stable_id,
                object_manifests:$manifests,
                recomputed_object_count:($manifests | length),
                recomputed_row_count:([$manifests[].row_count] | add)}))
           and ($backup.verified_aggregate_manifest_digest
                == $backup.aggregate_manifest_digest) ] | all)
  and ([ $verification.durable_object_aggregates[]
         | .recomputed_object_count == (.object_manifests | length)
           and .recomputed_row_count == ([.object_manifests[].row_count] | add)
           and .result == "pass" ] | all);

def gc_contract_valid($plan; $report):
  ($plan.gc_gate.cutover_check_ids | sort) as $cutover
  | ($plan.gc_gate.post_cutover_check_ids | sort) as $post
  | ($report.gc_gate.outstanding_check_ids | sort) as $outstanding
  | ($plan.gc_gate.outstanding_blocker_check_ids | sort) as $planned_outstanding
  | ([$plan.gc_gate.enablement_requires[].check_id] | sort) as $enablement
  | ([ $cutover[] as $check_id
       | select($post | index($check_id) != null) ] | length) == 0
  and (($cutover + $post) | sort) == $enablement
  and $planned_outstanding == $outstanding
  and (if $plan.gc_gate.readiness == "ready"
       then $planned_outstanding == [] and $post == []
       else $planned_outstanding == $post and ($post|length) > 0 end)
  and ([ $cutover[] as $check_id
         | reported_checks($report) | any(.check_id == $check_id and .result == "pass") ] | all)
  and ([ $post[] as $check_id
         | [reported_checks($report)[] | select(.check_id == $check_id)] as $checks
         | ($checks | length) == 1 and $checks[0].result == "not_run" ] | all)
  and $plan.gc_gate.destructive_gc_enabled_during_cutover == false
  and $report.gc_gate.destructive_gc_state_at_switch == "disabled"
  and (if $report.gc_gate.readiness == "ready"
       then $outstanding == [] and $report.gc_gate.inventory_gate == "complete"
            and $report.gc_gate.retention_gate == "fresh"
       else ($outstanding | length) > 0 end);

def auth_contract_valid($plan):
  ($plan.auth_no_widening) as $auth
  | ([ $auth.source_principal_stable_ids[] as $principal
       | $auth.source_scope_stable_ids[] as $scope
       | {principal_stable_id:$principal,scope_stable_id:$scope} ]
     | sort_by(.principal_stable_id,.scope_stable_id)) as $pairs
  | ($auth.expected_principal_scope_pairs | sort_by(.principal_stable_id,.scope_stable_id)) == $pairs
  and ($auth.principal_proofs | map({principal_stable_id,scope_stable_id})
       | sort_by(.principal_stable_id,.scope_stable_id)) == $pairs
  and $auth.principal_coverage.expected_count == ($pairs|length)
  and $auth.principal_coverage.proved_count == ($pairs|length)
  and $auth.principal_coverage.missing_count == 0
  and $auth.principal_coverage.duplicate_count == 0
  and ([ $auth.principal_proofs[]
         | (.source_permissions | sort | unique) as $source
         | (.target_permissions | sort | unique) as $target
         | (.source_permissions | length) == ($source|length)
           and (.target_permissions | length) == ($target|length)
           and ([$target[] | select($source|index(.) == null)] | length) == 0
           and (if $source == $target then .assertion == "equal"
                else .assertion == "narrower" end) ] | all)
  and ($auth.route_proofs | map(.route_stable_id) | sort)
      == ($plan.topology.routes | map(.stable_id) | sort)
  and ([ $plan.topology.routes[] as $route
         | ($plan.topology.route_configurations
            | map(select(.stable_id == $route.configuration_generation_stable_id))[0]) as $configuration
         | ($auth.route_proofs
            | map(select(.route_stable_id == $route.stable_id))[0]) as $proof
         | $configuration != null and $proof != null
           and $proof.target_access_policy == $route.access_policy
           and $proof.target_policy_configuration_digest == $configuration.configuration_digest
           and (if $proof.source_access_policy == $proof.target_access_policy
                then $proof.assertion == "equal"
                elif $proof.source_access_policy == "public"
                then $proof.assertion == "narrower"
                else false end) ] | all);

def outcome_contract_valid($plan; $report):
  if $report.result == "succeeded" then
    $report.failure == null
    and $report.switch.state == "completed"
    and $report.switch.write_admission_after_switch == "opened_after_validation"
    and $report.rollback.state == "closed_unused"
    and $report.rollback.rollback_boundary_crossed
    and ([reported_checks($report)[] as $check
          | $check.result == "pass"
            or ($check.result == "not_run"
                and ($report.gc_gate.outstanding_check_ids | index($check.check_id) != null))] | all)
    and ([$report.smoke_tests[] | .result == "pass"] | all)
    and ([$report.blockers[] | .state == "resolved"] | all)
  elif $report.result == "rolled_back" then
    $report.failure != null
    and $report.switch.write_admission_after_switch == "closed"
    and $report.rollback.state == "executed"
    and ($report.rollback.rollback_boundary_crossed | not)
    and $report.rollback.new_runtime_writes_before_closure == 0
    and $report.rollback.restore_set_result == "pass"
    and $report.rollback.old_deployment_restored == "verified"
    and $report.rollback.old_runtime_smoke_result == "pass"
    and $report.rollback.old_writes_reopened_after_verification
  else
    $report.failure != null
    and $report.switch.write_admission_after_switch == "closed"
    and ($report.rollback.state == "not_required" or
         ($report.rollback.state == "closed_failed"
          and $report.rollback.restore_failed_count > 0
          and $report.rollback.restore_set_result == "failed"
          and any($report.rollback.database_restores[]; .status == "failed")))
    and ($report.rollback.old_writes_reopened_after_verification | not)
  end;

def verification_contract_valid($plan; $report; $verification):
  $verification.schema_version == "aos.hub.topology-cutover-verification/v1"
  and $verification.document_kind == "cutover_verification"
  and $verification.dialect == "aos-cutover-schema/v1"
  and $verification.bundle_id == $plan.bundle_id
  and $report.bundle_id == $plan.bundle_id
  and $verification.result == "verified"
  and $verification.verifier_identity.byte_identity_matches
  and $verification.verifier_identity.bundle_entry_sha256
      == $verification.verifier_identity.current_exe_sha256
  and $verification.verifier_identity.trust_basis == "out_of_band_running_executable"
  and $verification.schema_validation.dialect == "aos-cutover-schema/v1"
  and $verification.schema_validation.unsupported_keyword_count == 0
  and $verification.schema_validation.result == "pass"
  and $verification.reference_validation.result == "pass"
  and ($verification.reference_validation.categories | length) == 13
  and $verification.database_restore_validation.planned_database_count == ($plan.source.databases | length)
  and $verification.database_restore_validation.missing_count == 0
  and $verification.database_restore_validation.unexpected_count == 0
  and $verification.database_restore_validation.result == "pass"
  and $verification.blocker_validation.expected_count == ($plan.blockers | length)
  and $verification.blocker_validation.actual_count == ($report.blockers | length)
  and $verification.transition_validation.attempt_id == $report.attempt.attempt_id
  and $verification.transition_validation.attempt_ordinal == $report.attempt.ordinal
  and $verification.transition_validation.idempotency_key_matches
  and $verification.transition_validation.predecessor_chain_valid
  and $verification.transition_validation.admitted_target_write_count == 0
  and $verification.gc_validation.partition_overlap_count == 0
  and $verification.gc_validation.undeclared_outstanding_count == 0
  and $verification.gc_validation.destructive_gc_disabled
  and $verification.fixture_validation.native_zero_do_case_passed
  and $verification.fixture_validation.failed_count == 0;

def canonical_order_valid($plan; $report; $verification):
  $plan.source.resource_nodes == ($plan.source.resource_nodes | sort_by(.resource_kind, .node_id))
  and $plan.source.databases == ($plan.source.databases | sort_by(.stable_id))
  and $plan.source.databases == ($plan.source.databases | unique_by(.stable_id))
  and $plan.backup == ($plan.backup | sort_by(.database_stable_id))
  and $report.backup == ($report.backup | sort_by(.database_stable_id))
  and $plan.switch.quiescence_targets == ($plan.switch.quiescence_targets | sort_by(.kind, .stable_id))
  and ($plan.switch.quiescence_targets | length) == ($plan.switch.quiescence_targets | unique_by(.kind, .stable_id) | length)
  and $plan.transform.stable_id_rules == ($plan.transform.stable_id_rules | sort_by(.resource_kind))
  and ($plan.transform.stable_id_rules | length) == ($plan.transform.stable_id_rules | unique_by(.resource_kind) | length)
  and $plan.validation.count_invariants == ($plan.validation.count_invariants | sort_by(.name))
  and ($plan.validation.count_invariants | length) == ($plan.validation.count_invariants | unique_by(.name) | length)
  and $plan.validation.digest_invariants == ($plan.validation.digest_invariants | sort_by(.name))
  and ($plan.validation.digest_invariants | length) == ($plan.validation.digest_invariants | unique_by(.name) | length)
  and $plan.topology.mapping_edges == ($plan.topology.mapping_edges | sort_by(.target_resource_kind, .target_stable_id))
  and $plan.scope.resource_stable_ids == ($plan.scope.resource_stable_ids | sort_by(.kind, .stable_id))
  and ([ ["instances", "organizations", "projects", "surfaces", "bindings",
        "binding_capability_observations", "credential_generations",
        "binding_write_revisions", "binding_grants", "storage_defaults",
        "placements", "write_authorities", "delivery_endpoints", "domains",
        "network_boundaries", "gateways", "routes", "route_configurations",
        "placement_policies", "equivalence_sets", "registry_publications",
        "publication_bindings", "population_targets", "placement_manifests"][] as $name
       | $plan.topology[$name] == ($plan.topology[$name] | sort_by(.stable_id))
         and ($plan.topology[$name] | length) == ($plan.topology[$name] | unique_by(.stable_id) | length) ] | all)
  and $plan.topology.retention_subscriptions == ($plan.topology.retention_subscriptions | sort_by(.cache_stable_id, .registry_stable_id, .stable_id))
  and $plan.topology.inventories == ($plan.topology.inventories | sort_by(.cache_stable_id, .generation))
  and ([ $plan.topology.inventories[]
         | .placement_manifests == (.placement_manifests | sort_by(.placement_stable_id, .manifest_stable_id))
           and (.placement_manifests | length)
               == (.placement_manifests | unique_by(.placement_stable_id, .manifest_stable_id) | length) ] | all)
  and ([ $plan.topology.bindings[]
         | .credential_refs == (.credential_refs | sort_by(.purpose, .stable_id, .version))
           and (.credential_refs | length)
               == (.credential_refs | unique_by(.purpose, .stable_id, .version) | length) ] | all)
  and ([ $plan.topology.routes[]
         | .backend_placement_stable_ids == (.backend_placement_stable_ids | sort)
           and (.backend_placement_stable_ids | length) == (.backend_placement_stable_ids | unique | length) ] | all)
  and $plan.auth_no_widening.source_principal_stable_ids == ($plan.auth_no_widening.source_principal_stable_ids | sort | unique)
  and $plan.auth_no_widening.source_scope_stable_ids == ($plan.auth_no_widening.source_scope_stable_ids | sort | unique)
  and $plan.auth_no_widening.expected_principal_scope_pairs == ($plan.auth_no_widening.expected_principal_scope_pairs | sort_by(.principal_stable_id, .scope_stable_id))
  and $plan.auth_no_widening.principal_proofs == ($plan.auth_no_widening.principal_proofs | sort_by(.scope_stable_id, .principal_stable_id))
  and ([ $plan.auth_no_widening.principal_proofs[]
         | .source_permissions == (.source_permissions | sort | unique)
           and .target_permissions == (.target_permissions | sort | unique) ] | all)
  and $plan.auth_no_widening.route_proofs == ($plan.auth_no_widening.route_proofs | sort_by(.route_stable_id))
  and $plan.gc_gate.cutover_check_ids == ($plan.gc_gate.cutover_check_ids | sort | unique)
  and $plan.gc_gate.post_cutover_check_ids == ($plan.gc_gate.post_cutover_check_ids | sort | unique)
  and $plan.gc_gate.outstanding_blocker_check_ids == ($plan.gc_gate.outstanding_blocker_check_ids | sort | unique)
  and $report.gc_gate.outstanding_check_ids == ($report.gc_gate.outstanding_check_ids | sort | unique)
  and $plan.validation.required_checks == ($plan.validation.required_checks | sort_by(.check_id))
  and $plan.gc_gate.enablement_requires == ($plan.gc_gate.enablement_requires | sort_by(.check_id))
  and $report.preflight.online_checks == ($report.preflight.online_checks | sort_by(.check_id))
  and $report.validation.checks == ($report.validation.checks | sort_by(.check_id))
  and $plan.smoke_tests == ($plan.smoke_tests | sort_by(.test_id))
  and $report.smoke_tests == ($report.smoke_tests | sort_by(.test_id))
  and $plan.blockers == ($plan.blockers | sort_by(.blocker_id))
  and $report.blockers == ($report.blockers | sort_by(.blocker_id))
  and $report.attempt_history == ($report.attempt_history | sort_by(.ordinal))
  and $report.transition_ledger == ($report.transition_ledger | sort_by(.sequence))
  and $report.rollback.database_restores == ($report.rollback.database_restores | sort_by(.database_stable_id))
  and $report.rollback.backup_artifacts == ($report.rollback.backup_artifacts | sort_by(.artifact_node_id))
  and $plan.rollback.restore_backups == ($plan.rollback.restore_backups | sort | unique)
  and $report.maintenance.targets == ($report.maintenance.targets | sort_by(.kind, .stable_id))
  and ($report.maintenance.targets | length) == ($report.maintenance.targets | unique_by(.kind, .stable_id) | length)
  and $verification.database_restore_validation.proofs == ($verification.database_restore_validation.proofs | sort_by(.database_stable_id))
  and ($verification.database_restore_validation.proofs | length) == ($verification.database_restore_validation.proofs | unique_by(.database_stable_id) | length)
  and $verification.durable_object_aggregates == ($verification.durable_object_aggregates | sort_by(.database_stable_id))
  and ($verification.durable_object_aggregates | length) == ($verification.durable_object_aggregates | unique_by(.database_stable_id) | length)
  and $verification.recomputed_topology.source_cardinalities == ($verification.recomputed_topology.source_cardinalities | sort_by(.source_node_id))
  and ($verification.recomputed_topology.source_cardinalities | length) == ($verification.recomputed_topology.source_cardinalities | unique_by(.source_node_id) | length)
  and $verification.reference_validation.categories == ($verification.reference_validation.categories | sort_by(.category))
  and ($verification.reference_validation.categories | length) == ($verification.reference_validation.categories | unique_by(.category) | length)
  and $verification.schema_validation.validated_schema_node_ids == ($verification.schema_validation.validated_schema_node_ids | sort | unique)
  and $verification.schema_validation.validated_document_node_ids == ($verification.schema_validation.validated_document_node_ids | sort | unique)
  and ([ $report.backup[] | select(.database_kind == "durable_object_sqlite")
         | .object_manifests == (.object_manifests | sort_by(canonical_json_text))
           and (.object_manifests | map(canonical_json_text) | length)
               == (.object_manifests | map(canonical_json_text) | unique | length) ] | all);

def validate($plan; $report; $verification):
  require($plan.dialect == "aos-cutover-schema/v1"
          and $report.dialect == "aos-cutover-schema/v1";
          "dialect_mismatch"; "/dialect")
  + require($report.plan.plan_id == $plan.plan_id;
            "plan_reference_mismatch"; "/plan")
  + require(mapping_contract_valid($plan);
            "mapping_contract_invalid"; "/topology/mapping_edges")
  + require(reference_contract_valid($plan);
            "reference_contract_invalid"; "/topology")
  + require(auth_contract_valid($plan);
            "auth_contract_invalid"; "/auth_no_widening")
  + require(check_contract_valid($plan; $report);
            "check_contract_invalid"; "/validation/checks")
  + require(blocker_contract_valid($plan; $report);
            "blocker_contract_invalid"; "/blockers")
  + require(smoke_contract_valid($plan; $report);
            "smoke_contract_invalid"; "/smoke_tests")
  + require(attempt_contract_valid($plan; $report);
            "attempt_contract_invalid"; "/attempt_history")
  + require(transition_contract_valid($plan; $report);
            "transition_contract_invalid"; "/transition_ledger")
  + require(database_contract_valid($plan; $report; $verification);
            "database_restore_contract_invalid"; "/rollback/database_restores")
  + require(do_aggregate_contract_valid($report; $verification);
            "durable_object_aggregate_invalid"; "/durable_object_aggregates")
  + require(gc_contract_valid($plan; $report);
            "gc_partition_invalid"; "/gc_gate")
  + require(outcome_contract_valid($plan; $report);
            "outcome_contract_invalid"; "/result")
  + require(verification_contract_valid($plan; $report; $verification);
            "verification_contract_invalid"; "/verification")
  + require(canonical_order_valid($plan; $report; $verification);
            "canonical_order_invalid"; "/");
