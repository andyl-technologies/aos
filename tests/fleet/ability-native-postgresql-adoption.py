# Stateful PostgreSQL provider replacement, interruption, and retention flight.
NATIVE_OWNER_LEDGER = "/var/lib/profiles/system/.ability-native-resources.json"
ADOPTION_CONSUMER = "ability-reference-postgresql-consumer"
ADOPTION_CONFIGURATION = "postgresql-provider-adoption"
ADOPTION_CREDENTIAL_VERSION = "sha256:" + "70" * 32
ADOPTION_MATERIALIZE_OPERATION = (
    "materialize-postgresql-provider-adoption-postgresql"
)
ADOPTION_RESTART_OPERATION = "restart-postgresql-provider-adoption-postgresql"
ADOPTION_START_OPERATION = "start-postgresql-provider-adoption-postgresql"
POSTGRESQL_COHORT_SUBJECT_SCHEMA = (
    "aos.qualification.postgresql-provider-replacement-cohort-subject/v1"
)
POSTGRESQL_REJECTION_EVIDENCE_SCHEMA = (
    "aos.qualification.postgresql-provider-rejection-evidence/v1"
)


def adoption_package(artifact):
    return f"ability-reference-postgresql-{artifact}"


def adoption_host(path, activation, artifact):
    write_postgresql_host(
        path,
        activation,
        desired_package_names=[ADOPTION_CONSUMER, adoption_package(artifact)],
    )


def owner_for_activation(activation):
    resource = resource_entries(activation)["postgresql"]["resource"]
    owners = [
        owner
        for owner in read_json(NATIVE_OWNER_LEDGER).get("owners", [])
        if owner["resource"] == resource
    ]
    assert len(owners) == 1, (resource, owners)
    return owners[0]


def postgresql_resource(activation):
    return resource_entries(activation)["postgresql"]["resource"]


def transition_operation_key(
    bundle,
    method,
    resource,
    expected_local_key,
):
    operations = bundle["transition"]["effect_document"]["operations"]
    matching = [
        operation
        for operation in operations
        if operation["method"] == method
        and operation["target"]["resource"] == resource
    ]
    assert len(matching) == 1, (method, resource, matching, operations)
    scoped_key = matching[0]["key"]
    assert scoped_key["key"] == expected_local_key, (scoped_key, matching[0])
    return scoped_key


def assert_adoption_replacement_edges(bundle, resource):
    stop_key = transition_operation_key(
        bundle,
        "stop",
        resource,
        "stop-postgresql-provider-adoption-postgresql",
    )
    materialize_key = transition_operation_key(
        bundle,
        "materialize",
        resource,
        ADOPTION_MATERIALIZE_OPERATION,
    )
    restart_key = transition_operation_key(
        bundle,
        "restart",
        resource,
        ADOPTION_RESTART_OPERATION,
    )
    required_edges = [
        {
            "from": {"kind": "operation", "key": stop_key},
            "to": {"kind": "operation", "key": materialize_key},
            "kind": "required-success",
        },
        {
            "from": {"kind": "operation", "key": materialize_key},
            "to": {"kind": "operation", "key": restart_key},
            "kind": "required-success",
        },
    ]
    observed_edges = bundle["transition"]["effect_document"]["edges"]
    for edge in required_edges:
        assert edge in observed_edges, (edge, observed_edges)


def expected_owner_provenance(
    owner,
    generation,
    transaction,
    bundle,
    method,
    resource,
    expected_local_key,
):
    operation_key = transition_operation_key(
        bundle,
        method,
        resource,
        expected_local_key,
    )
    return {
        "generation": generation,
        "transaction": transaction,
        "plan": bundle["plan"],
        "operation": {
            "plan": bundle["plan"],
            "operation": operation_key,
        },
        "attempt": 1,
        "artifacts": bundle["transition"]["effect_document"]["artifacts"],
    }


def assert_established_owner_provenance(
    owner,
    generation,
    transaction,
    bundle,
    method,
    resource,
    expected_local_key,
):
    expected = expected_owner_provenance(
        owner,
        generation,
        transaction,
        bundle,
        method,
        resource,
        expected_local_key,
    )
    assert owner["generation"] == generation, owner
    assert owner["transaction"] == transaction, owner
    assert owner["plan"] == bundle["plan"], (owner, bundle)
    assert owner["established_by"] == expected, (owner, expected)
    assert owner.get("claim_by", []) == [], owner
    assert "claim_by" not in owner, owner
    assert "adoption" not in owner, owner
    return expected


def canonical_records(records):
    return sorted(
        json.dumps(record, sort_keys=True, separators=(",", ":"))
        for record in records
    )


def canonical_json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def evidence_digest(value):
    payload = value if isinstance(value, bytes) else canonical_json_bytes(value)
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def operation_projection(bundle, method, resource):
    matches = [
        {
            "key": operation["key"],
            "ordinal": ordinal,
            "interface": operation["interface"],
            "method": operation["method"],
            "target": operation["target"],
        }
        for ordinal, operation in enumerate(
            bundle["transition"]["effect_document"]["operations"]
        )
        if operation["method"] == method
        and operation["target"]["resource"] == resource
    ]
    assert len(matches) == 1, (method, resource, matches)
    return matches[0]


def required_success_dependents(bundle, operation):
    effect_document = bundle["transition"]["effect_document"]
    operations = effect_document["operations"]
    by_key = {
        canonical_json_bytes(candidate["key"]): {
            "key": candidate["key"],
            "ordinal": ordinal,
            "interface": candidate["interface"],
            "method": candidate["method"],
            "target": candidate["target"],
        }
        for ordinal, candidate in enumerate(operations)
    }
    assert len(by_key) == len(operations), operations
    dependent_keys = [
        edge["to"]["key"]
        for edge in effect_document["edges"]
        if edge["kind"] == "required-success"
        and edge["from"] == {"kind": "operation", "key": operation["key"]}
        and edge["to"]["kind"] == "operation"
    ]
    return [by_key[canonical_json_bytes(key)] for key in dependent_keys]


def postgresql_cohort_subject(bundle, method, bundle_bytes):
    adoption = adoption_contract(bundle)
    authority = bundle["transition_authority"]
    operation = operation_projection(bundle, method, adoption["resource"])
    return {
        "schema": POSTGRESQL_COHORT_SUBJECT_SCHEMA,
        "plan": bundle["plan"],
        "evidence-digest": evidence_digest(bundle_bytes),
        "operation": operation,
        "dependent-operations": required_success_dependents(bundle, operation),
        "resource": adoption["resource"],
        "resource-interface": adoption["resource_interface"],
        "source": adoption["source"],
        "candidate": adoption["candidate"],
        "authorization-policy-revision": authority[
            "authorization_policy_revision"
        ],
        "current-planning": authority["current_planning"],
        "desired-planning": authority["desired_planning"],
    }


def postgresql_rejection_subject(activation, policy, evidence_bytes):
    authority = policy["transition_authority"]
    adoption = authority["provider_adoptions"][0]
    candidate = adoption["candidate"]
    policy_bytes = canonical_json_bytes(policy)
    pinned = activation["authenticated_policy_set"]
    assert pinned["document_sha256"] == evidence_digest(policy_bytes), pinned
    assert pinned["document_size"] == len(policy_bytes), pinned
    operation = {
        "key": candidate["handler_binding"],
        "ordinal": 0,
        "interface": candidate["handler_interface"],
        "method": candidate["handler_method"],
        "target": {
            "interface": candidate["handler_interface"],
            "resource": adoption["resource"],
            "operations": [candidate["handler_method"]],
            "lifetime": "persistent",
        },
    }
    return {
        "schema": POSTGRESQL_COHORT_SUBJECT_SCHEMA,
        "plan": authority["desired_planning"],
        "evidence-digest": evidence_digest(evidence_bytes),
        "operation": operation,
        "dependent-operations": [],
        "resource": adoption["resource"],
        "resource-interface": adoption["resource_interface"],
        "source": adoption["source"],
        "candidate": candidate,
        "authorization-policy-revision": authority[
            "authorization_policy_revision"
        ],
        "current-planning": authority["current_planning"],
        "desired-planning": authority["desired_planning"],
    }


def sidecar_document(activation, name):
    sidecar = activation[name]
    path = sidecar["store_path"] + "/" + sidecar["document"]
    document_bytes = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(path)}"
    ).encode()
    document = json.loads(document_bytes)
    assert canonical_json_bytes(document) == document_bytes, path
    assert evidence_digest(document_bytes) == sidecar["document_sha256"], sidecar
    assert len(document_bytes) == sidecar["document_size"], sidecar
    return document


def operation_timeline(generation, transaction, operation):
    diagnostic = json.loads(runtime.succeed(
        f"{AOS} --json ability diagnostic "
        f"/var/lib/profiles/system/gen-{generation} "
        f"{shlex.quote(transaction)}"
    ))
    return [
        {
            "sequence": event["sequence"],
            "kind": event["kind"],
            "node-ordinal": event["node_ordinal"],
        }
        for event in diagnostic["timeline"]["events"]
        if event.get("node_ordinal") == operation["ordinal"]
    ]


def transaction_journal_digest(root):
    digest = runtime.succeed(
        f"{COREUTILS}/sha256sum {shlex.quote(root + '/execution.journal')}"
    ).split()[0]
    return f"sha256:{digest}"


def owner_inventory(resource):
    return [
        owner
        for owner in read_json(NATIVE_OWNER_LEDGER).get("owners", [])
        if owner["resource"] == resource
    ]


def postgresql_state_snapshot(activation, kind="host-storage"):
    state = resource_states(activation)[kind]
    return state["resource"], evidence_digest(state)


def adoption_row_digest(details, secret):
    row = application_psql(
        details,
        secret,
        "SELECT value FROM ability_provider_adoption",
    )
    assert row == "retained-through-provider-replacement", row
    return evidence_digest(row.encode())


def matrix_probe(kind, disposition, detail, observations):
    return {
        "kind": kind,
        "disposition": disposition,
        "detail": detail,
        "observations": observations,
    }


def adoption_contract(bundle):
    authority = bundle["transition_authority"]
    assert authority["required_features"] == [
        "provider-state-adoption-v1"
    ], authority
    adoptions = authority["provider_adoptions"]
    assert len(adoptions) == 1, adoptions
    adoption = adoptions[0]
    assert adoption["source"]["handler_method"] == "materialize", adoption
    assert adoption["candidate"]["handler_method"] == "materialize", adoption
    assert adoption["source"]["handler_binding"] != (
        adoption["candidate"]["handler_binding"]
    ), adoption
    return adoption


def assert_adoption_current_planning(bundle, retained_planning):
    authority = bundle["transition_authority"]
    assert authority["current_planning"] == retained_planning, (
        authority,
        retained_planning,
    )


def endpoint_identity(endpoint):
    return {
        "provider": endpoint["provider"],
        "package": endpoint["package"],
        "interface": endpoint["interface"],
        "implementation": endpoint["implementation"],
        "state_format": endpoint["state_format"],
    }


def endpoint_handler(endpoint):
    return {
        "package": endpoint["handler_package"],
        "provider": endpoint["handler_provider"],
        "interface": endpoint["handler_interface"],
        "implementation": endpoint["handler_implementation"],
    }


def assert_owner_endpoint(owner, endpoint):
    assert owner["identity"] == endpoint_identity(endpoint), (owner, endpoint)
    assert owner["handler"] == endpoint_handler(endpoint), (
        owner,
        endpoint,
    )


def assert_adoption_data(details, secret, expected_identifier):
    assert details["data_system_identifier"] == expected_identifier, details
    assert application_psql(
        details,
        secret,
        "SELECT value FROM ability_provider_adoption",
    ) == "retained-through-provider-replacement"


# Leave the saturated capacity fixture in an empty desired state. Its durable
# PostgreSQL allocation remains available for the first stateful owner.
activation_adoption_remove = generate_postgresql_activation(
    "/run/postgresql-adoption-remove",
    "ability_app",
    "ability_role",
    "sha256:" + "69" * 32,
    "postgresql-capacity-reuse",
    "/run/postgresql-authority-adoption-remove",
    lifecycle="remove",
    postgresql_artifact="upgrade",
)
provision_postgresql_authority(
    activation_adoption_remove,
    "/run/postgresql-authority-adoption-remove",
)
write_postgresql_host(
    "/run/postgresql-host-adoption-remove.nix",
    activation_adoption_remove,
    desired_package_names=[
        ADOPTION_CONSUMER,
        "ability-reference-postgresql-upgrade",
    ],
)
switch_postgresql_host(
    "/run/postgresql-host-adoption-remove.nix",
    "adoption-remove",
)

activation_adoption_v1 = generate_postgresql_activation(
    "/run/postgresql-adoption-v1",
    "ability_app",
    "ability_role",
    ADOPTION_CREDENTIAL_VERSION,
    ADOPTION_CONFIGURATION,
    "/run/postgresql-authority-adoption-v1",
    postgresql_artifact="adoption-v1",
)
provision_postgresql_authority(
    activation_adoption_v1,
    "/run/postgresql-authority-adoption-v1",
)
adoption_host(
    "/run/postgresql-host-adoption-v1.nix",
    activation_adoption_v1,
    "adoption-v1",
)
generation_adoption_v1 = switch_postgresql_host(
    "/run/postgresql-host-adoption-v1.nix",
    "adoption-v1",
)
transaction_adoption_v1, _, bundle_adoption_v1, _ = transaction_document(
    generation_adoption_v1
)
planning_adoption_v1 = bundle_adoption_v1["desired"]["snapshot_digest"]
details_adoption_v1 = assert_cluster_layout(
    resource_states(activation_adoption_v1)
)
secret_adoption_v1 = "/run/postgresql-adoption-v1/test-only/credential.secret"
application_psql(
    details_adoption_v1,
    secret_adoption_v1,
    "DROP TABLE IF EXISTS ability_provider_adoption; "
    "CREATE TABLE ability_provider_adoption(value text); "
    "INSERT INTO ability_provider_adoption VALUES "
    "('retained-through-provider-replacement')",
)
adoption_system_identifier = details_adoption_v1["data_system_identifier"]
adoption_data_path = details_adoption_v1["data_path"]
owner_adoption_v1 = owner_for_activation(activation_adoption_v1)
resource_adoption_v1 = postgresql_resource(activation_adoption_v1)
owners_adoption_v1 = owner_inventory(resource_adoption_v1)
foreign_resource_adoption_v1, foreign_snapshot_adoption_v1 = (
    postgresql_state_snapshot(activation_adoption_v1)
)
row_digest_adoption_v1 = adoption_row_digest(
    details_adoption_v1,
    secret_adoption_v1,
)
assert_established_owner_provenance(
    owner_adoption_v1,
    f"gen-{generation_adoption_v1}",
    transaction_adoption_v1,
    bundle_adoption_v1,
    "start",
    resource_adoption_v1,
    ADOPTION_START_OPERATION,
)

# An incompatible format is rejected before ledger publication or native work.
activation_adoption_incompatible = generate_postgresql_activation(
    "/run/postgresql-adoption-incompatible",
    "ability_app",
    "ability_role",
    ADOPTION_CREDENTIAL_VERSION,
    ADOPTION_CONFIGURATION,
    "/run/postgresql-authority-adoption-incompatible",
    postgresql_artifact="adoption-incompatible",
    provider_adoption_from="adoption-v1",
    provider_adoption_current_planning=planning_adoption_v1,
)
provision_postgresql_authority(
    activation_adoption_incompatible,
    "/run/postgresql-authority-adoption-incompatible",
)
adoption_host(
    "/run/postgresql-host-adoption-incompatible.nix",
    activation_adoption_incompatible,
    "adoption-incompatible",
)
ledger_before_incompatible = runtime.succeed(
    f"{COREUTILS}/cat {NATIVE_OWNER_LEDGER}"
)
policy_adoption_incompatible = sidecar_document(
    activation_adoption_incompatible,
    "authenticated_policy_set",
)
states_before_incompatible = persistent_state_snapshot()
generation_before_incompatible = current_generation()
incompatible_error = switch_postgresql_host(
    "/run/postgresql-host-adoption-incompatible.nix",
    "adoption-incompatible",
    succeed=False,
)
assert "state-format descriptors are incompatible" in incompatible_error, (
    incompatible_error
)
assert current_generation() == generation_before_incompatible
assert runtime.succeed(f"{COREUTILS}/cat {NATIVE_OWNER_LEDGER}") == (
    ledger_before_incompatible
)
assert persistent_state_snapshot() == states_before_incompatible
generation_after_incompatible = current_generation()
ledger_after_incompatible = runtime.succeed(
    f"{COREUTILS}/cat {NATIVE_OWNER_LEDGER}"
)
states_after_incompatible = persistent_state_snapshot()
rejection_evidence_adoption_incompatible = canonical_json_bytes({
    "schema": POSTGRESQL_REJECTION_EVIDENCE_SCHEMA,
    "activation": activation_adoption_incompatible,
    "policy": policy_adoption_incompatible,
    "observation": {
        "error": incompatible_error,
        "generation-before": generation_before_incompatible,
        "generation-after": generation_after_incompatible,
        "owner-ledger-before": evidence_digest(ledger_before_incompatible.encode()),
        "owner-ledger-after": evidence_digest(ledger_after_incompatible.encode()),
        "persistent-state-before": evidence_digest(states_before_incompatible),
        "persistent-state-after": evidence_digest(states_after_incompatible),
        "candidate-effect-count": 0,
    },
})
subject_adoption_incompatible = postgresql_rejection_subject(
    activation_adoption_incompatible,
    policy_adoption_incompatible,
    rejection_evidence_adoption_incompatible,
)
owners_after_incompatible = owner_inventory(resource_adoption_v1)
foreign_resource_after_incompatible, foreign_snapshot_after_incompatible = (
    postgresql_state_snapshot(activation_adoption_v1)
)
row_digest_after_incompatible = adoption_row_digest(
    details_adoption_v1,
    secret_adoption_v1,
)
assert foreign_resource_after_incompatible == foreign_resource_adoption_v1

# A normal compatible replacement changes both the owner and the real
# PostgreSQL executable while retaining the cluster identity and SQL data.
activation_adoption_v2 = generate_postgresql_activation(
    "/run/postgresql-adoption-v2",
    "ability_app",
    "ability_role",
    ADOPTION_CREDENTIAL_VERSION,
    ADOPTION_CONFIGURATION,
    "/run/postgresql-authority-adoption-v2",
    postgresql_artifact="adoption-v2",
    provider_adoption_from="adoption-v1",
    provider_adoption_current_planning=planning_adoption_v1,
)
provision_postgresql_authority(
    activation_adoption_v2,
    "/run/postgresql-authority-adoption-v2",
)
adoption_host(
    "/run/postgresql-host-adoption-v2.nix",
    activation_adoption_v2,
    "adoption-v2",
)
generation_adoption_v2 = switch_postgresql_host(
    "/run/postgresql-host-adoption-v2.nix",
    "adoption-v2",
)
transaction_adoption_v2, root_adoption_v2, bundle_adoption_v2, _ = transaction_document(
    generation_adoption_v2
)
bundle_bytes_adoption_v2 = runtime.succeed(
    f"{COREUTILS}/cat {shlex.quote(root_adoption_v2 + '/plan-bundle.json')}"
).encode()
assert_adoption_current_planning(bundle_adoption_v2, planning_adoption_v1)
planning_adoption_v2 = bundle_adoption_v2["desired"]["snapshot_digest"]
contract_adoption_v2 = adoption_contract(bundle_adoption_v2)
assert owner_adoption_v1["identity"] == endpoint_identity(
    contract_adoption_v2["source"]
)
owner_adoption_v2 = owner_for_activation(activation_adoption_v2)
assert_owner_endpoint(owner_adoption_v2, contract_adoption_v2["candidate"])
resource_adoption_v2 = postgresql_resource(activation_adoption_v2)
subject_adoption_v2 = postgresql_cohort_subject(
    bundle_adoption_v2,
    "materialize",
    bundle_bytes_adoption_v2,
)
assert_adoption_replacement_edges(bundle_adoption_v2, resource_adoption_v2)
assert_established_owner_provenance(
    owner_adoption_v2,
    f"gen-{generation_adoption_v2}",
    transaction_adoption_v2,
    bundle_adoption_v2,
    "restart",
    resource_adoption_v2,
    ADOPTION_RESTART_OPERATION,
)
details_adoption_v2 = assert_cluster_layout(
    resource_states(activation_adoption_v2)
)
secret_adoption_v2 = "/run/postgresql-adoption-v2/test-only/credential.secret"
assert details_adoption_v2["postgres_executable"] != (
    details_adoption_v1["postgres_executable"]
)
assert details_adoption_v2["data_path"] == adoption_data_path
assert_adoption_data(
    details_adoption_v2,
    secret_adoption_v2,
    adoption_system_identifier,
)
row_digest_adoption_v2 = adoption_row_digest(
    details_adoption_v2,
    secret_adoption_v2,
)
owners_adoption_v2 = owner_inventory(resource_adoption_v2)
foreign_resource_adoption_v2, foreign_snapshot_adoption_v2 = (
    postgresql_state_snapshot(activation_adoption_v2)
)
timeline_adoption_v2 = operation_timeline(
    generation_adoption_v2,
    transaction_adoption_v2,
    subject_adoption_v2["operation"],
)
journal_digest_adoption_v2 = transaction_journal_digest(root_adoption_v2)

# Return to v1 so the interrupted transition has a unique source artifact.
activation_adoption_v1_return = generate_postgresql_activation(
    "/run/postgresql-adoption-v1-return",
    "ability_app",
    "ability_role",
    ADOPTION_CREDENTIAL_VERSION,
    ADOPTION_CONFIGURATION,
    "/run/postgresql-authority-adoption-v1-return",
    postgresql_artifact="adoption-v1",
    provider_adoption_from="adoption-v2",
    provider_adoption_current_planning=planning_adoption_v2,
)
provision_postgresql_authority(
    activation_adoption_v1_return,
    "/run/postgresql-authority-adoption-v1-return",
)
adoption_host(
    "/run/postgresql-host-adoption-v1-return.nix",
    activation_adoption_v1_return,
    "adoption-v1",
)
generation_adoption_v1_return = switch_postgresql_host(
    "/run/postgresql-host-adoption-v1-return.nix",
    "adoption-v1-return",
)
(
    transaction_adoption_v1_return,
    _,
    bundle_adoption_v1_return,
    _,
) = transaction_document(generation_adoption_v1_return)
assert_adoption_current_planning(
    bundle_adoption_v1_return,
    planning_adoption_v2,
)
planning_adoption_v1_return = bundle_adoption_v1_return["desired"][
    "snapshot_digest"
]
details_adoption_v1_return = assert_cluster_layout(
    resource_states(activation_adoption_v1_return)
)
owner_adoption_v1_return = owner_for_activation(
    activation_adoption_v1_return
)
resource_adoption_v1_return = postgresql_resource(
    activation_adoption_v1_return
)
assert_adoption_replacement_edges(
    bundle_adoption_v1_return,
    resource_adoption_v1_return,
)
establishment_adoption_v1_return = assert_established_owner_provenance(
    owner_adoption_v1_return,
    f"gen-{generation_adoption_v1_return}",
    transaction_adoption_v1_return,
    bundle_adoption_v1_return,
    "restart",
    resource_adoption_v1_return,
    ADOPTION_RESTART_OPERATION,
)
assert_adoption_data(
    details_adoption_v1_return,
    "/run/postgresql-adoption-v1-return/test-only/credential.secret",
    adoption_system_identifier,
)
owners_adoption_v1_return = owner_inventory(resource_adoption_v1_return)
foreign_resource_before_interrupted, foreign_snapshot_before_interrupted = (
    postgresql_state_snapshot(activation_adoption_v1_return)
)
row_digest_adoption_v1_return = adoption_row_digest(
    details_adoption_v1_return,
    "/run/postgresql-adoption-v1-return/test-only/credential.secret",
)

# Interrupt the candidate after PostgreSQL starts but before the effect is
# recorded. The atomic preflight receipt roots both exact implementations.
activation_adoption_interrupted = generate_postgresql_activation(
    "/run/postgresql-adoption-interrupted",
    "ability_app",
    "ability_role",
    ADOPTION_CREDENTIAL_VERSION,
    ADOPTION_CONFIGURATION,
    "/run/postgresql-authority-adoption-interrupted",
    postgresql_artifact="adoption-v2-interrupted",
    provider_adoption_from="adoption-v1",
    provider_adoption_current_planning=planning_adoption_v1_return,
)
provision_postgresql_authority(
    activation_adoption_interrupted,
    "/run/postgresql-authority-adoption-interrupted",
)
interrupted_host = "/run/postgresql-host-adoption-interrupted.nix"
adoption_host(
    interrupted_host,
    activation_adoption_interrupted,
    "adoption-v2-interrupted",
)
interrupted_marker = state_path(
    resource_entries(activation_adoption_interrupted)["postgresql"]
)
runtime.succeed(f"{COREUTILS}/rm -f {recovery_release}")
interrupted_status, interrupted_log = start_background_switch(
    interrupted_host,
    "adoption-interrupted",
)
interrupted_details, interrupted_postmaster = (
    wait_for_unrecorded_quarantine_start(interrupted_marker)
)
owner_interrupted = owner_for_activation(activation_adoption_interrupted)
receipt_interrupted = owner_interrupted["adoption"]
pending_generation = owner_interrupted["generation"]
pending_transaction = owner_interrupted["transaction"]
pending_bundle = read_json(
    f"/var/lib/profiles/system/{pending_generation}/ability-transactions/"
    f"{pending_transaction}/plan-bundle.json"
)
pending_root = (
    f"/var/lib/profiles/system/{pending_generation}/ability-transactions/"
    f"{pending_transaction}"
)
pending_bundle_bytes = runtime.succeed(
    f"{COREUTILS}/cat {shlex.quote(pending_root + '/plan-bundle.json')}"
).encode()
contract_interrupted = adoption_contract(pending_bundle)
assert_adoption_current_planning(
    pending_bundle,
    planning_adoption_v1_return,
)
assert_owner_endpoint(owner_interrupted, contract_interrupted["candidate"])
resource_adoption_interrupted = postgresql_resource(
    activation_adoption_interrupted
)
subject_adoption_interrupted = postgresql_cohort_subject(
    pending_bundle,
    "restart",
    pending_bundle_bytes,
)
assert subject_adoption_interrupted["dependent-operations"] == [], (
    subject_adoption_interrupted
)
owners_adoption_interrupted = owner_inventory(resource_adoption_interrupted)
assert_adoption_replacement_edges(
    pending_bundle,
    resource_adoption_interrupted,
)
expected_interrupted_materialize = expected_owner_provenance(
    owner_interrupted,
    pending_generation,
    pending_transaction,
    pending_bundle,
    "materialize",
    resource_adoption_interrupted,
    ADOPTION_MATERIALIZE_OPERATION,
)
expected_interrupted_restart = expected_owner_provenance(
    owner_interrupted,
    pending_generation,
    pending_transaction,
    pending_bundle,
    "restart",
    resource_adoption_interrupted,
    ADOPTION_RESTART_OPERATION,
)
assert owner_interrupted["generation"] == pending_generation, owner_interrupted
assert owner_interrupted["transaction"] == pending_transaction, owner_interrupted
assert owner_interrupted["plan"] == pending_bundle["plan"], owner_interrupted
assert "established_by" not in owner_interrupted, owner_interrupted
assert canonical_records(owner_interrupted.get("claim_by", [])) == (
    canonical_records(
        [expected_interrupted_materialize, expected_interrupted_restart]
    )
), owner_interrupted
assert receipt_interrupted["authority"] == (
    pending_bundle["transition_authority_digest"]
), (receipt_interrupted, pending_bundle)
assert "consumer_requirement" not in receipt_interrupted, receipt_interrupted
assert "linked_verification" not in receipt_interrupted, receipt_interrupted
assert receipt_interrupted["source"] == endpoint_identity(
    contract_interrupted["source"]
)
assert receipt_interrupted["source_handler"] == endpoint_handler(
    contract_interrupted["source"]
)
assert receipt_interrupted["source_generation"] == (
    f"gen-{generation_adoption_v1_return}"
)
assert receipt_interrupted["source_establishment"] == (
    establishment_adoption_v1_return
), receipt_interrupted
assert receipt_interrupted["source_generation"] == (
    receipt_interrupted["source_establishment"]["generation"]
), receipt_interrupted
assert receipt_interrupted["source_transaction"] == (
    receipt_interrupted["source_establishment"]["transaction"]
), receipt_interrupted
assert receipt_interrupted["source_plan"] == (
    receipt_interrupted["source_establishment"]["plan"]
), receipt_interrupted
for artifact in receipt_interrupted["source_establishment"]["artifacts"]:
    assert artifact in receipt_interrupted["source_artifacts"], (
        artifact,
        receipt_interrupted,
    )
expected_source_artifacts = [
    receipt_interrupted["source"]["implementation"]["artifact"],
    receipt_interrupted["source"]["state_format"]["artifact"],
    receipt_interrupted["source_handler"]["implementation"]["artifact"],
]
for artifact in expected_source_artifacts:
    assert artifact in receipt_interrupted["source_artifacts"], (
        artifact,
        receipt_interrupted,
    )
source_state_artifact = receipt_interrupted["source"]["state_format"][
    "artifact"
]["store_path"]
candidate_state_artifact = owner_interrupted["identity"]["state_format"][
    "artifact"
]["store_path"]
assert source_state_artifact != candidate_state_artifact

kill_exact_postgresql_activation_runtime()
kill_held_postgresql_control()
runtime.wait_until_succeeds(f"test -s {interrupted_status}", timeout=120)
assert runtime.succeed(f"{COREUTILS}/cat {interrupted_status}").strip() != "0", (
    runtime.succeed(f"{COREUTILS}/cat {interrupted_log}")
)
runtime.succeed(f"kill -0 {interrupted_postmaster}")

clean_interrupted = json.loads(runtime.succeed(
    f"{APM} --json clean --system --generations --keep 1",
    timeout=600,
))
retained_interrupted = clean_interrupted["configuration"]["generations_after"]
assert generation_adoption_v1_return in retained_interrupted, clean_interrupted
assert int(pending_generation.removeprefix("gen-")) in retained_interrupted, (
    clean_interrupted
)
runtime.succeed(f"{APM} gc", timeout=600)
for path in (source_state_artifact, candidate_state_artifact):
    runtime.succeed(f"test -e {shlex.quote(path)}")

runtime.succeed(
    f"{COREUTILS}/install -o root -g root -m 0600 /dev/null "
    f"{recovery_release}"
)
generation_adoption_recovered = switch_postgresql_host(
    interrupted_host,
    "adoption-interrupted-recovery",
)
assert generation_adoption_recovered == int(
    pending_generation.removeprefix("gen-")
)
transaction_adoption_recovered, root_adoption_recovered, bundle_adoption_recovered, _ = (
    assert_single_postgresql_reconciliation(
        generation_adoption_recovered,
        activation_adoption_interrupted,
        "restart",
    )
)
assert transaction_adoption_recovered == pending_transaction, (
    transaction_adoption_recovered,
    pending_transaction,
)
assert bundle_adoption_recovered["plan"] == pending_bundle["plan"], (
    bundle_adoption_recovered,
    pending_bundle,
)
owner_adoption_recovered = owner_for_activation(
    activation_adoption_interrupted
)
assert_owner_endpoint(
    owner_adoption_recovered,
    contract_interrupted["candidate"],
)
establishment_adoption_recovered = assert_established_owner_provenance(
    owner_adoption_recovered,
    pending_generation,
    pending_transaction,
    pending_bundle,
    "restart",
    resource_adoption_interrupted,
    ADOPTION_RESTART_OPERATION,
)
assert establishment_adoption_recovered == expected_interrupted_restart, (
    establishment_adoption_recovered,
    expected_interrupted_restart,
)
details_adoption_recovered = assert_cluster_layout(
    resource_states(activation_adoption_interrupted)
)
assert details_adoption_recovered["process"]["pid"] != int(
    interrupted_postmaster
)
assert_adoption_data(
    details_adoption_recovered,
    "/run/postgresql-adoption-interrupted/test-only/credential.secret",
    adoption_system_identifier,
)
assert_runtime_redaction(
    generation_adoption_recovered,
    transaction_adoption_recovered,
    [],
)
owners_adoption_recovered = owner_inventory(resource_adoption_interrupted)
foreign_resource_after_recovery, foreign_snapshot_after_recovery = (
    postgresql_state_snapshot(activation_adoption_interrupted)
)
assert foreign_resource_after_recovery == foreign_resource_before_interrupted
row_digest_adoption_recovered = adoption_row_digest(
    details_adoption_recovered,
    "/run/postgresql-adoption-interrupted/test-only/credential.secret",
)
timeline_adoption_recovered = operation_timeline(
    generation_adoption_recovered,
    transaction_adoption_recovered,
    subject_adoption_interrupted["operation"],
)
journal_digest_adoption_recovered = transaction_journal_digest(
    root_adoption_recovered
)

# Once the exact terminal marker retires the receipt, the old source
# generation and unique v1 state-format artifact are collectible.
clean_completed = json.loads(runtime.succeed(
    f"{APM} --json clean --system --generations --keep 1",
    timeout=600,
))
assert generation_adoption_v1_return in clean_completed["configuration"][
    "removed_generations"
], clean_completed
runtime.succeed(f"{APM} gc", timeout=600)
runtime.fail(f"test -e {shlex.quote(source_state_artifact)}")
runtime.succeed(f"test -e {shlex.quote(candidate_state_artifact)}")

# Reinstalling v1 and explicitly adopting from the recovered candidate keeps
# the same target state after the old implementation was collected.
activation_adoption_final_v1 = generate_postgresql_activation(
    "/run/postgresql-adoption-final-v1",
    "ability_app",
    "ability_role",
    ADOPTION_CREDENTIAL_VERSION,
    ADOPTION_CONFIGURATION,
    "/run/postgresql-authority-adoption-final-v1",
    postgresql_artifact="adoption-v1",
    provider_adoption_from="adoption-v2-interrupted",
    provider_adoption_current_planning=pending_bundle["desired"]["snapshot_digest"],
)
provision_postgresql_authority(
    activation_adoption_final_v1,
    "/run/postgresql-authority-adoption-final-v1",
)
adoption_host(
    "/run/postgresql-host-adoption-final-v1.nix",
    activation_adoption_final_v1,
    "adoption-v1",
)
generation_adoption_final_v1 = switch_postgresql_host(
    "/run/postgresql-host-adoption-final-v1.nix",
    "adoption-final-v1",
)
(
    transaction_adoption_final_v1,
    root_adoption_final_v1,
    bundle_adoption_final_v1,
    _,
) = transaction_document(generation_adoption_final_v1)
bundle_bytes_adoption_final_v1 = runtime.succeed(
    f"{COREUTILS}/cat "
    f"{shlex.quote(root_adoption_final_v1 + '/plan-bundle.json')}"
).encode()
assert_adoption_current_planning(
    bundle_adoption_final_v1,
    pending_bundle["desired"]["snapshot_digest"],
)
owner_adoption_final_v1 = owner_for_activation(
    activation_adoption_final_v1
)
assert_owner_endpoint(
    owner_adoption_final_v1,
    adoption_contract(bundle_adoption_final_v1)["candidate"],
)
resource_adoption_final_v1 = postgresql_resource(
    activation_adoption_final_v1
)
subject_adoption_final_v1 = postgresql_cohort_subject(
    bundle_adoption_final_v1,
    "restart",
    bundle_bytes_adoption_final_v1,
)
assert_adoption_replacement_edges(
    bundle_adoption_final_v1,
    resource_adoption_final_v1,
)
assert_established_owner_provenance(
    owner_adoption_final_v1,
    f"gen-{generation_adoption_final_v1}",
    transaction_adoption_final_v1,
    bundle_adoption_final_v1,
    "restart",
    resource_adoption_final_v1,
    ADOPTION_RESTART_OPERATION,
)
details_adoption_final_v1 = assert_cluster_layout(
    resource_states(activation_adoption_final_v1)
)
assert_adoption_data(
    details_adoption_final_v1,
    "/run/postgresql-adoption-final-v1/test-only/credential.secret",
    adoption_system_identifier,
)
row_digest_adoption_final_v1 = adoption_row_digest(
    details_adoption_final_v1,
    "/run/postgresql-adoption-final-v1/test-only/credential.secret",
)
owners_adoption_final_v1 = owner_inventory(resource_adoption_final_v1)
foreign_resource_adoption_final_v1, foreign_snapshot_adoption_final_v1 = (
    postgresql_state_snapshot(activation_adoption_final_v1)
)
timeline_adoption_final_v1 = operation_timeline(
    generation_adoption_final_v1,
    transaction_adoption_final_v1,
    subject_adoption_final_v1["operation"],
)
journal_digest_adoption_final_v1 = transaction_journal_digest(
    root_adoption_final_v1
)

compatible_cell = (
    "postgresql/aos.postgresql-effects/abi-1/materialize/"
    "adopt-compatible-state"
)
incompatible_cell = (
    "postgresql/aos.postgresql-effects/abi-1/materialize/"
    "reject-unsupported-transfer"
)
interrupted_cell = (
    "postgresql/aos.postgresql-effects/abi-1/restart/"
    "lose-external-result"
)
retained_cell = (
    "postgresql/aos.postgresql-effects/abi-1/restart/"
    "activate-retained-target"
)

NATIVE_ADAPTER_MATRIX_COHORT_SUBJECTS = {
    compatible_cell: subject_adoption_v2,
    incompatible_cell: subject_adoption_incompatible,
    interrupted_cell: subject_adoption_interrupted,
    retained_cell: subject_adoption_final_v1,
}
NATIVE_ADAPTER_MATRIX_COHORT_EVIDENCE = {
    compatible_cell: bundle_bytes_adoption_v2,
    incompatible_cell: rejection_evidence_adoption_incompatible,
    interrupted_cell: pending_bundle_bytes,
    retained_cell: bundle_bytes_adoption_final_v1,
}
NATIVE_ADAPTER_MATRIX_PROBES = {
    compatible_cell: {
        "durable-attempt-state-classified": matrix_probe(
            "journal-timeline",
            "compatible-state-adopted",
            "The production journal completed the exact PostgreSQL materialize operation.",
            {
                "transaction": transaction_adoption_v2,
                "plan": bundle_adoption_v2["plan"],
                "operation": subject_adoption_v2["operation"],
                "timeline": timeline_adoption_v2,
                "record-digest": journal_digest_adoption_v2,
                "terminal": "complete",
                "classified": True,
            },
        ),
        "at-most-one-resource-owner": matrix_probe(
            "ownership-inventory",
            "compatible-state-adopted",
            "The atomic owner ledger retained at most one owner while materialize adopted the cluster.",
            {
                "resource": resource_adoption_v2,
                "owners-before": owners_adoption_v1,
                "owners-unsettled": [],
                "owners-after": owners_adoption_v2,
            },
        ),
        "foreign-resources-unchanged": matrix_probe(
            "foreign-resource-snapshot",
            "compatible-state-adopted",
            "The independently owned storage marker retained exact canonical state.",
            {
                "resource": foreign_resource_adoption_v1,
                "snapshot-before": foreign_snapshot_adoption_v1,
                "snapshot-after": foreign_snapshot_adoption_v2,
                "unchanged": (
                    foreign_snapshot_adoption_v1 == foreign_snapshot_adoption_v2
                ),
            },
        ),
        "fresh-receiving-authority": matrix_probe(
            "authority-incarnation",
            "compatible-state-adopted",
            "The transition pins distinct source and candidate handler incarnations under current policy.",
            {
                "source-handler-incarnation": subject_adoption_v2["source"]
                ["handler_incarnation"],
                "candidate-handler-incarnation": subject_adoption_v2["candidate"]
                ["handler_incarnation"],
                "authorization-policy-revision": subject_adoption_v2[
                    "authorization-policy-revision"
                ],
                "current-planning": subject_adoption_v2["current-planning"],
                "desired-planning": subject_adoption_v2["desired-planning"],
                "fresh": True,
            },
        ),
        "compatible-state-adopted": matrix_probe(
            "state-adoption",
            "compatible-state-adopted",
            "The changed PostgreSQL executable preserved the real cluster identifier and query result.",
            {
                "resource": resource_adoption_v2,
                "source-state-format": subject_adoption_v2["source"][
                    "state_format"
                ],
                "candidate-state-format": subject_adoption_v2["candidate"]
                ["state_format"],
                "system-identifier-before": adoption_system_identifier,
                "system-identifier-after": details_adoption_v2[
                    "data_system_identifier"
                ],
                "row-digest-before": row_digest_adoption_v1,
                "row-digest-after": row_digest_adoption_v2,
                "adopted": True,
            },
        ),
        "exactly-one-resource-owner": matrix_probe(
            "exact-ownership-inventory",
            "compatible-state-adopted",
            "The durable ledger names only the exact candidate endpoint after adoption.",
            {
                "resource": resource_adoption_v2,
                "expected-owner": owner_adoption_v2,
                "owners": owners_adoption_v2,
            },
        ),
    },
    incompatible_cell: {
        "durable-attempt-state-classified": matrix_probe(
            "journal-timeline",
            "transfer-rejected-before-effect",
            "The pinned incompatible policy input was rejected before a transaction journal existed.",
            {
                "transaction": "planning-rejection",
                "plan": subject_adoption_incompatible["plan"],
                "operation": subject_adoption_incompatible["operation"],
                "timeline": [],
                "record-digest": evidence_digest(
                    rejection_evidence_adoption_incompatible
                ),
                "terminal": "rejected-before-effect",
                "classified": True,
            },
        ),
        "at-most-one-resource-owner": matrix_probe(
            "ownership-inventory",
            "transfer-rejected-before-effect",
            "The predecessor remained the ledger's sole owner across rejection.",
            {
                "resource": resource_adoption_v1,
                "owners-before": owners_adoption_v1,
                "owners-unsettled": owners_adoption_v1,
                "owners-after": owners_after_incompatible,
            },
        ),
        "foreign-resources-unchanged": matrix_probe(
            "foreign-resource-snapshot",
            "transfer-rejected-before-effect",
            "The separately owned storage state retained its exact canonical digest.",
            {
                "resource": foreign_resource_adoption_v1,
                "snapshot-before": foreign_snapshot_adoption_v1,
                "snapshot-after": foreign_snapshot_after_incompatible,
                "unchanged": (
                    foreign_snapshot_adoption_v1
                    == foreign_snapshot_after_incompatible
                ),
            },
        ),
        "dependent-effects-not-executed": matrix_probe(
            "dependency-barrier",
            "transfer-rejected-before-effect",
            "No candidate or successor operation acquired a transaction before rejection.",
            {
                "predecessor-operation": subject_adoption_incompatible[
                    "operation"
                ],
                "dependent-operations": subject_adoption_incompatible[
                    "dependent-operations"
                ],
                "dependent-timelines-before-settlement": [],
                "dependent-effect-count-before-settlement": 0,
                "blocked": True,
            },
        ),
        "fresh-receiving-authority": matrix_probe(
            "authority-incarnation",
            "transfer-rejected-before-effect",
            "The rejected contract still pins the exact fresh candidate authority.",
            {
                "source-handler-incarnation": subject_adoption_incompatible[
                    "source"
                ]["handler_incarnation"],
                "candidate-handler-incarnation": subject_adoption_incompatible[
                    "candidate"
                ]["handler_incarnation"],
                "authorization-policy-revision": subject_adoption_incompatible[
                    "authorization-policy-revision"
                ],
                "current-planning": subject_adoption_incompatible[
                    "current-planning"
                ],
                "desired-planning": subject_adoption_incompatible[
                    "desired-planning"
                ],
                "fresh": True,
            },
        ),
        "transfer-rejected-before-candidate-effect": matrix_probe(
            "transfer-rejection",
            "transfer-rejected-before-effect",
            "Exact unequal state-format descriptors rejected before generation or native effect.",
            {
                "candidate-operation": subject_adoption_incompatible["operation"],
                "source-state-format": subject_adoption_incompatible["source"]
                ["state_format"],
                "candidate-state-format": subject_adoption_incompatible[
                    "candidate"
                ]["state_format"],
                "rejection": "transfer-rejected",
                "candidate-effect-count": 0,
                "generation-before": generation_before_incompatible,
                "generation-after": generation_after_incompatible,
                "rejected-before-effect": True,
            },
        ),
        "predecessor-remains-sole-owner": matrix_probe(
            "predecessor-ownership",
            "transfer-rejected-before-effect",
            "The live predecessor kept the same owner, cluster identifier, and query result.",
            {
                "resource": resource_adoption_v1,
                "predecessor-owner-before": owner_adoption_v1,
                "predecessor-owner-after": owners_after_incompatible[0],
                "system-identifier-before": adoption_system_identifier,
                "system-identifier-after": details_adoption_v1[
                    "data_system_identifier"
                ],
                "row-digest-before": row_digest_adoption_v1,
                "row-digest-after": row_digest_after_incompatible,
            },
        ),
    },
    interrupted_cell: {
        "durable-attempt-state-classified": matrix_probe(
            "journal-timeline",
            "reconciled-completed",
            "Executor and handler loss left one restart attempt that replay reconciled without retry.",
            {
                "transaction": transaction_adoption_recovered,
                "plan": pending_bundle["plan"],
                "operation": subject_adoption_interrupted["operation"],
                "timeline": timeline_adoption_recovered,
                "record-digest": journal_digest_adoption_recovered,
                "terminal": "complete",
                "classified": True,
            },
        ),
        "at-most-one-resource-owner": matrix_probe(
            "ownership-inventory",
            "reconciled-completed",
            "The atomic receipt kept one candidate owner before and after recovery.",
            {
                "resource": resource_adoption_interrupted,
                "owners-before": owners_adoption_v1_return,
                "owners-unsettled": owners_adoption_interrupted,
                "owners-after": owners_adoption_recovered,
            },
        ),
        "foreign-resources-unchanged": matrix_probe(
            "foreign-resource-snapshot",
            "reconciled-completed",
            "Storage outside the PostgreSQL owner transfer retained exact state through GC and replay.",
            {
                "resource": foreign_resource_before_interrupted,
                "snapshot-before": foreign_snapshot_before_interrupted,
                "snapshot-after": foreign_snapshot_after_recovery,
                "unchanged": (
                    foreign_snapshot_before_interrupted
                    == foreign_snapshot_after_recovery
                ),
            },
        ),
        "dependent-effects-not-executed": matrix_probe(
            "dependency-barrier",
            "reconciled-completed",
            "The exact interrupted restart has no required-success successors to admit before settlement.",
            {
                "predecessor-operation": subject_adoption_interrupted["operation"],
                "dependent-operations": subject_adoption_interrupted[
                    "dependent-operations"
                ],
                "dependent-timelines-before-settlement": [],
                "dependent-effect-count-before-settlement": 0,
                "blocked": True,
            },
        ),
    },
    retained_cell: {
        "durable-attempt-state-classified": matrix_probe(
            "journal-timeline",
            "retained-target-activated",
            "The final restart completed under a new plan after the old source artifact was collected.",
            {
                "transaction": transaction_adoption_final_v1,
                "plan": bundle_adoption_final_v1["plan"],
                "operation": subject_adoption_final_v1["operation"],
                "timeline": timeline_adoption_final_v1,
                "record-digest": journal_digest_adoption_final_v1,
                "terminal": "complete",
                "classified": True,
            },
        ),
        "at-most-one-resource-owner": matrix_probe(
            "ownership-inventory",
            "retained-target-activated",
            "The final adoption replaced the recovered owner atomically.",
            {
                "resource": resource_adoption_final_v1,
                "owners-before": owners_adoption_recovered,
                "owners-unsettled": [],
                "owners-after": owners_adoption_final_v1,
            },
        ),
        "foreign-resources-unchanged": matrix_probe(
            "foreign-resource-snapshot",
            "retained-target-activated",
            "The independent storage provider preserved its state through final adoption.",
            {
                "resource": foreign_resource_after_recovery,
                "snapshot-before": foreign_snapshot_after_recovery,
                "snapshot-after": foreign_snapshot_adoption_final_v1,
                "unchanged": (
                    foreign_snapshot_after_recovery
                    == foreign_snapshot_adoption_final_v1
                ),
            },
        ),
        "current-grants-reauthorized": matrix_probe(
            "authority-grants",
            "retained-target-activated",
            "The final plan bound the retained source and new candidate under current policy.",
            {
                "authorization-policy-revision": subject_adoption_final_v1[
                    "authorization-policy-revision"
                ],
                "source-handler-incarnation": subject_adoption_final_v1["source"]
                ["handler_incarnation"],
                "candidate-handler-incarnation": subject_adoption_final_v1[
                    "candidate"
                ]["handler_incarnation"],
                "current-planning": subject_adoption_final_v1[
                    "current-planning"
                ],
                "desired-planning": subject_adoption_final_v1[
                    "desired-planning"
                ],
                "reauthorized": True,
            },
        ),
        "retained-target-identity-preserved": matrix_probe(
            "target-identity",
            "retained-target-activated",
            "The final provider kept the same durable data path, cluster identifier, and query result.",
            {
                "resource": resource_adoption_final_v1,
                "data-path-before": details_adoption_recovered["data_path"],
                "data-path-after": details_adoption_final_v1["data_path"],
                "system-identifier-before": details_adoption_recovered[
                    "data_system_identifier"
                ],
                "system-identifier-after": details_adoption_final_v1[
                    "data_system_identifier"
                ],
                "row-digest-before": row_digest_adoption_recovered,
                "row-digest-after": row_digest_adoption_final_v1,
            },
        ),
        "exactly-one-resource-owner": matrix_probe(
            "exact-ownership-inventory",
            "retained-target-activated",
            "The ledger names only the reinstalled production v1 endpoint.",
            {
                "resource": resource_adoption_final_v1,
                "expected-owner": owner_adoption_final_v1,
                "owners": owners_adoption_final_v1,
            },
        ),
    },
}
