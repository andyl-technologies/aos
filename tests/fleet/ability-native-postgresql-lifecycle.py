# Baseline, no-op, rotation, same-major upgrade, repair, and retention flight.
runtime.start()
runtime.wait_for_unit("multi-user.target", timeout=300)
assert_root_layout()
assert_slot_accounts()
publish_postgresql_packages()
assert_package_closure_boundary()

activation_v1 = generate_postgresql_activation(
    "/run/postgresql-v1",
    "ability_app",
    "ability_role",
    "sha256:" + "11" * 32,
    "postgresql-v1",
    "/run/postgresql-authority-v1",
)
provision_postgresql_authority(
    activation_v1,
    "/run/postgresql-authority-v1",
)
write_postgresql_host("/run/postgresql-host-v1.nix", activation_v1)
generation_v1 = switch_postgresql_host(
    "/run/postgresql-host-v1.nix",
    "v1",
)
assert_postgresql_packages_installed()

create_operations = {
    ("credential-delivery", "deliver"),
    ("network-endpoint", "materialize"),
    ("host-storage", "ensure"),
    ("host-network-policy", "apply"),
    ("postgresql", "materialize"),
    ("postgresql", "start"),
    ("postgresql", "observe"),
}
transaction_v1, transaction_root_v1, bundle_v1 = assert_effect_graph(
    generation_v1,
    activation_v1,
    create_operations,
    10,
)
states_v1 = resource_states(activation_v1)
details_v1 = assert_cluster_layout(states_v1)
assert_candidate_publication(details_v1)
assert_process_boundary(details_v1)
assert_identity_isolation(
    details_v1,
    states_v1["credential-delivery"]["details"]["view_path"],
)
assert_root_control_rejected(
    details_v1,
    states_v1["postgresql"]["qualification"],
)
secret_v1 = "/run/postgresql-v1/test-only/credential.secret"
assert_sql_ready(details_v1, secret_v1)
secret_text_v1 = runtime.succeed(
    f"{COREUTILS}/cat {shlex.quote(secret_v1)}"
).rstrip("\n")
assert_runtime_redaction(
    generation_v1,
    transaction_v1,
    [secret_text_v1],
)

snapshot_v1 = protected_snapshot(states_v1, details_v1)
activation_noop = generate_postgresql_activation(
    "/run/postgresql-noop",
    "ability_app",
    "ability_role",
    "sha256:" + "11" * 32,
    "postgresql-v1",
    "/run/postgresql-authority-noop",
)
provision_postgresql_authority(
    activation_noop,
    "/run/postgresql-authority-noop",
)
write_postgresql_host("/run/postgresql-host-noop.nix", activation_noop)
generation_noop = switch_postgresql_host(
    "/run/postgresql-host-noop.nix",
    "noop",
)
noop_operations = {
    ("credential-delivery", "acquire"),
    ("network-endpoint", "observe"),
    ("host-storage", "observe"),
    ("host-network-policy", "observe"),
    ("postgresql", "observe"),
}
transaction_noop, _, bundle_noop = assert_effect_graph(
    generation_noop,
    activation_noop,
    noop_operations,
    5,
)
assert_required_edge(
    bundle_noop,
    activation_noop,
    ("host-network-policy", "observe"),
    ("postgresql", "observe"),
)
states_noop = resource_states(activation_noop)
assert states_noop == states_v1, (states_noop, states_v1)
assert protected_snapshot(states_noop, details_v1) == snapshot_v1
assert_sql_ready(details_v1, secret_v1)
assert_runtime_redaction(
    generation_noop,
    transaction_noop,
    [secret_text_v1],
)

activation_v2 = generate_postgresql_activation(
    "/run/postgresql-v2",
    "ability_app",
    "ability_role",
    "sha256:" + "22" * 32,
    "postgresql-v2",
    "/run/postgresql-authority-v2",
)
provision_postgresql_authority(
    activation_v2,
    "/run/postgresql-authority-v2",
)
write_postgresql_host("/run/postgresql-host-v2.nix", activation_v2)
generation_v2 = switch_postgresql_host(
    "/run/postgresql-host-v2.nix",
    "v2",
)
update_operations = {
    ("credential-delivery", "deliver"),
    ("network-endpoint", "observe"),
    ("host-storage", "observe"),
    ("host-network-policy", "observe"),
    ("postgresql", "materialize"),
    ("postgresql", "restart"),
    ("postgresql", "observe"),
}
transaction_v2, _, _ = assert_effect_graph(
    generation_v2,
    activation_v2,
    update_operations,
    10,
)
states_v2 = resource_states(activation_v2)
details_v2 = states_v2["postgresql"]["details"]
secret_v2 = "/run/postgresql-v2/test-only/credential.secret"
secret_text_v2 = runtime.succeed(
    f"{COREUTILS}/cat {shlex.quote(secret_v2)}"
).rstrip("\n")
assert secret_text_v2 != secret_text_v1
assert details_v2["slot"] == details_v1["slot"]
assert details_v2["data_system_identifier"] == (
    details_v1["data_system_identifier"]
)
assert details_v2["role_verifier_digest"] != (
    details_v1["role_verifier_digest"]
)
assert postmaster_identity(details_v2)[0] != snapshot_v1["postmaster"][0]
assert_sql_ready(details_v2, secret_v2)
runtime.fail(
    f"{COREUTILS}/cat {shlex.quote(secret_v1)} | {PSQL} "
    "-X --no-psqlrc -W --set ON_ERROR_STOP=1 "
    f"-h 127.0.0.1 -p {details_v2['endpoint']['port']} "
    f"-U {shlex.quote(details_v2['role'])} "
    f"-d {shlex.quote(details_v2['database'])} -c 'SELECT 1'",
    timeout=30,
)
assert_runtime_redaction(
    generation_v2,
    transaction_v2,
    [secret_text_v1, secret_text_v2],
)

verifier_before_upgrade = details_v2["role_verifier_digest"]
system_identifier_before_upgrade = details_v2["data_system_identifier"]
activation_upgrade = generate_postgresql_activation(
    "/run/postgresql-upgrade",
    "ability_app",
    "ability_role",
    "sha256:" + "22" * 32,
    "postgresql-upgrade",
    "/run/postgresql-authority-upgrade",
    postgresql_artifact="upgrade",
)
provision_postgresql_authority(
    activation_upgrade,
    "/run/postgresql-authority-upgrade",
)
write_postgresql_host(
    "/run/postgresql-host-upgrade.nix",
    activation_upgrade,
)
generation_upgrade = switch_postgresql_host(
    "/run/postgresql-host-upgrade.nix",
    "upgrade",
)
transaction_upgrade, _, _ = assert_effect_graph(
    generation_upgrade,
    activation_upgrade,
    update_operations - {("credential-delivery", "deliver")}
    | {("credential-delivery", "acquire")},
    10,
)
states_upgrade = resource_states(activation_upgrade)
details_upgrade = states_upgrade["postgresql"]["details"]
qualification_upgrade = states_upgrade["postgresql"]["qualification"]
assert qualification_upgrade["postgresql_major"] == 18
assert qualification_upgrade["control"]["store_path"].endswith(
    "-ability-reference-postgresql-control-upgrade"
)
assert qualification_upgrade["postgresql"]["store_path"].endswith(
    "-ability-reference-postgresql-distribution-upgrade-1.0.0"
)
assert details_upgrade["data_system_identifier"] == (
    system_identifier_before_upgrade
)
assert details_upgrade["role_verifier_digest"] == verifier_before_upgrade
assert postmaster_identity(details_upgrade)[1].startswith(
    qualification_upgrade["postgresql"]["store_path"] + "/"
)
assert_sql_ready(details_upgrade, secret_v2)
assert_runtime_redaction(
    generation_upgrade,
    transaction_upgrade,
    [secret_text_v1, secret_text_v2],
)

admin_psql(
    details_upgrade,
    'CREATE ROLE "ability_escalation" SUPERUSER; '
    'CREATE ROLE "ability_delegate" LOGIN; '
    'GRANT "ability_escalation" TO "ability_role"; '
    'GRANT "ability_role" TO "ability_delegate"',
)
assert admin_psql(
    details_upgrade,
    "SELECT count(*) FROM pg_auth_members AS membership "
    "JOIN pg_roles AS application_role "
    "ON application_role.oid = membership.member "
    "OR application_role.oid = membership.roleid "
    "WHERE application_role.rolname = 'ability_role'",
) == "2"
assert application_psql(
    details_upgrade,
    secret_v2,
    'SET ROLE "ability_escalation"; SELECT current_user',
) == "ability_escalation"

write_postgresql_host(
    "/run/postgresql-host-membership-drift.nix",
    activation_upgrade,
)
switch_postgresql_host(
    "/run/postgresql-host-membership-drift.nix",
    "membership-drift",
    succeed=False,
)
generation_membership_repair = switch_postgresql_host(
    "/run/postgresql-host-membership-drift.nix",
    "membership-repair",
)
transaction_membership_repair, _, _ = assert_effect_graph(
    generation_membership_repair,
    activation_upgrade,
    update_operations - {("credential-delivery", "deliver")}
    | {("credential-delivery", "acquire")},
    10,
)
states_membership_repair = resource_states(activation_upgrade)
details_membership_repair = states_membership_repair["postgresql"][
    "details"
]
assert admin_psql(
    details_membership_repair,
    "SELECT count(*) FROM pg_auth_members AS membership "
    "JOIN pg_roles AS member_role "
    "ON member_role.oid = membership.member "
    "JOIN pg_roles AS parent_role "
    "ON parent_role.oid = membership.roleid "
    "WHERE member_role.rolname = 'ability_role' "
    "OR parent_role.rolname = 'ability_role'",
) == "0"
application_psql(
    details_membership_repair,
    secret_v2,
    'SET ROLE "ability_escalation"',
    succeed=False,
)
assert_sql_ready(details_membership_repair, secret_v2)
assert_runtime_redaction(
    generation_membership_repair,
    transaction_membership_repair,
    [secret_text_v1, secret_text_v2],
)

application_psql(
    details_membership_repair,
    secret_v2,
    "CREATE TABLE ability_retained(value text); "
    "INSERT INTO ability_retained VALUES ('survived')",
)
retained_system_identifier = details_membership_repair[
    "data_system_identifier"
]
retained_slot = details_membership_repair["slot"]
retained_data_path = details_membership_repair["data_path"]
retained_storage_marker = state_path(
    resource_entries(activation_upgrade)["host-storage"]
)
retained_postgresql_marker = state_path(
    resource_entries(activation_upgrade)["postgresql"]
)
ephemeral_paths = [
    state_path(resource_entries(activation_upgrade)[kind])
    for kind in (
        "credential-delivery",
        "network-endpoint",
        "host-network-policy",
    )
]
old_postmaster_pid = postmaster_identity(details_membership_repair)[0]

activation_remove = generate_postgresql_activation(
    "/run/postgresql-remove",
    "ability_app",
    "ability_role",
    "sha256:" + "22" * 32,
    "postgresql-upgrade",
    "/run/postgresql-authority-remove",
    lifecycle="remove",
    postgresql_artifact="upgrade",
)
provision_postgresql_authority(
    activation_remove,
    "/run/postgresql-authority-remove",
)
assert native_resource_map(activation_remove)["entries"] == []
write_postgresql_host(
    "/run/postgresql-host-remove.nix",
    activation_remove,
)
generation_remove = switch_postgresql_host(
    "/run/postgresql-host-remove.nix",
    "remove",
)
teardown_operations = {
    ("credential-delivery", "release"),
    ("network-endpoint", "materialize"),
    ("network-endpoint", "release"),
    ("host-storage", "release"),
    ("host-network-policy", "remove"),
    ("postgresql", "stop"),
}
transaction_remove, _, bundle_remove = assert_effect_graph(
    generation_remove,
    activation_remove,
    teardown_operations,
    5,
    resource_activation=activation_upgrade,
)
assert_required_edge(
    bundle_remove,
    activation_remove,
    ("postgresql", "stop"),
    ("credential-delivery", "release"),
    resource_activation=activation_upgrade,
)
assert_required_edge(
    bundle_remove,
    activation_remove,
    ("postgresql", "stop"),
    ("network-endpoint", "materialize"),
    resource_activation=activation_upgrade,
)
assert_required_edge(
    bundle_remove,
    activation_remove,
    ("network-endpoint", "materialize"),
    ("host-network-policy", "remove"),
    resource_activation=activation_upgrade,
)
assert_required_edge(
    bundle_remove,
    activation_remove,
    ("host-network-policy", "remove"),
    ("network-endpoint", "release"),
    resource_activation=activation_upgrade,
)
assert_required_edge(
    bundle_remove,
    activation_remove,
    ("network-endpoint", "release"),
    ("host-storage", "release"),
    resource_activation=activation_upgrade,
)
runtime.fail(f"kill -0 {old_postmaster_pid}")
runtime.succeed(f"test -d {shlex.quote(retained_data_path)}")
for path in (retained_storage_marker, retained_postgresql_marker):
    assert_protected_file(path, 0, 0, "600")
for path in ephemeral_paths:
    runtime.fail(f"test -e {shlex.quote(path)}")
released_postgresql = read_json(retained_postgresql_marker)
released_storage = read_json(retained_storage_marker)
assert released_postgresql["details"]["phase"] == "stopped"
assert released_storage["details"]["phase"] == "released"
assert released_postgresql["details"]["slot"] == retained_slot
assert_runtime_redaction(
    generation_remove,
    transaction_remove,
    [secret_text_v1, secret_text_v2],
)

activation_readd = generate_postgresql_activation(
    "/run/postgresql-readd",
    "ability_app",
    "ability_role",
    "sha256:" + "22" * 32,
    "postgresql-upgrade",
    "/run/postgresql-authority-readd",
    postgresql_artifact="upgrade",
)
provision_postgresql_authority(
    activation_readd,
    "/run/postgresql-authority-readd",
)
write_postgresql_host(
    "/run/postgresql-host-readd.nix",
    activation_readd,
)
generation_readd = switch_postgresql_host(
    "/run/postgresql-host-readd.nix",
    "readd",
)
transaction_readd, _, _ = assert_effect_graph(
    generation_readd,
    activation_readd,
    create_operations,
    10,
)
states_readd = resource_states(activation_readd)
details_readd = assert_cluster_layout(states_readd)
secret_readd = "/run/postgresql-readd/test-only/credential.secret"
assert details_readd["slot"] == retained_slot
assert details_readd["data_path"] == retained_data_path
assert details_readd["data_system_identifier"] == retained_system_identifier
assert application_psql(
    details_readd,
    secret_readd,
    "SELECT value FROM ability_retained",
) == "survived"
assert_sql_ready(details_readd, secret_readd)
assert_runtime_redaction(
    generation_readd,
    transaction_readd,
    [secret_text_v1, secret_text_v2],
)
