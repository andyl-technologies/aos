# Two live clusters must remain isolated across every physical authority path.


def state_for_resource(kind, resource):
    return read_json(state_path({
        "resource": resource,
        "qualification": {"kind": kind},
    }))


def fixture_secret_for_cluster(output, index, details):
    if index == 0:
        return output + "/test-only/credential.secret"
    digest = resource_digest(details["credential"]["resource"])
    return output + f"/test-only/credential-{digest}.secret"


activation_isolation = generate_postgresql_activation(
    "/run/postgresql-isolation",
    "ability_app",
    "ability_role",
    "sha256:" + "33" * 32,
    "postgresql-hold",
    "/run/postgresql-authority-isolation",
    additional=[(
        "isolation_database",
        "isolation_role",
        "sha256:" + "44" * 32,
        "postgresql-isolation",
    )],
)
provision_postgresql_authority(
    activation_isolation,
    "/run/postgresql-authority-isolation",
)
write_postgresql_host(
    "/run/postgresql-host-isolation.nix",
    activation_isolation,
)
generation_isolation = switch_postgresql_host(
    "/run/postgresql-host-isolation.nix",
    "isolation",
)

isolation_states = postgresql_states_by_cluster()
assert set(isolation_states) >= {
    "ability_app",
    "isolation_database",
}, isolation_states
details_isolation_a = isolation_states["ability_app"]["details"]
details_isolation_b = isolation_states["isolation_database"]["details"]
secret_isolation_a = fixture_secret_for_cluster(
    "/run/postgresql-isolation",
    0,
    details_isolation_a,
)
secret_isolation_b = fixture_secret_for_cluster(
    "/run/postgresql-isolation",
    1,
    details_isolation_b,
)

for details, secret in (
    (details_isolation_a, secret_isolation_a),
    (details_isolation_b, secret_isolation_b),
):
    assert_process_boundary(details)
    assert_candidate_publication(details)
    assert_sql_ready(details, secret)
    credential = state_for_resource(
        "credential-delivery",
        details["credential"]["resource"],
    )
    assert credential["details"]["view_path"] == (
        details["credential"]["view_path"]
    ), (credential, details)

assert details_isolation_a["slot"] != details_isolation_b["slot"]
assert details_isolation_a["uid"] != details_isolation_b["uid"]
assert details_isolation_a["data_path"] != details_isolation_b["data_path"]
assert details_isolation_a["run_path"] != details_isolation_b["run_path"]
assert details_isolation_a["endpoint"]["port"] != (
    details_isolation_b["endpoint"]["port"]
)
assert details_isolation_a["data_system_identifier"] != (
    details_isolation_b["data_system_identifier"]
)

for own, other, own_secret, other_secret in (
    (
        details_isolation_a,
        details_isolation_b,
        secret_isolation_a,
        secret_isolation_b,
    ),
    (
        details_isolation_b,
        details_isolation_a,
        secret_isolation_b,
        secret_isolation_a,
    ),
):
    own_drop = (
        f"{SETPRIV} --reuid={own['uid']} --regid=71 --clear-groups "
        "--no-new-privs --inh-caps=-all --ambient-caps=-all "
        "--bounding-set=-all"
    )
    runtime.fail(
        f"{own_drop} {COREUTILS}/cat "
        f"{shlex.quote(other['data_path'] + '/PG_VERSION')}"
    )
    runtime.fail(
        f"{own_drop} {PSQL} -X --no-psqlrc --set ON_ERROR_STOP=1 "
        f"-h {shlex.quote(other['run_path'])} "
        f"-p {other['server_port']} -U aos-ability-postgresql "
        "-d postgres -c 'SELECT 1'",
        timeout=30,
    )
    application_psql(own, other_secret, "SELECT 1", succeed=False)
    password = f"{COREUTILS}/cat {shlex.quote(other_secret)} | "
    runtime.fail(
        f"{password}{PSQL} -X --no-psqlrc -W --set ON_ERROR_STOP=1 "
        f"-h 127.0.0.1 -p {own['endpoint']['port']} "
        f"-U {shlex.quote(other['role'])} "
        f"-d {shlex.quote(other['database'])} -c 'SELECT 1'",
        timeout=30,
    )
    runtime.fail(
        f"{COREUTILS}/cmp -s {shlex.quote(own_secret)} "
        f"{shlex.quote(other_secret)}"
    )

transaction_isolation, root_isolation, bundle_isolation, _ = (
    transaction_document(generation_isolation)
)
assert_successful_transaction(
    generation_isolation,
    transaction_isolation,
    root_isolation,
    bundle_isolation,
)
