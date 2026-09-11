# Every fixed control-process crash cut must reconcile from its durable phase.


def run_postgresql_fault(
    index,
    fault,
    database,
    role,
    version,
    expected_phase,
    expected_method,
):
    label = f"fault-{index:02d}-{fault.removeprefix('crash-')}"
    output = f"/run/postgresql-{label}"
    authority = f"/run/postgresql-authority-{label}"
    activation = generate_postgresql_activation(
        output,
        database,
        role,
        version,
        label,
        authority,
        fault=fault,
    )
    provision_postgresql_authority(activation, authority)
    host = f"/run/postgresql-host-{label}.nix"
    write_postgresql_host(host, activation)
    postgresql_entry = resource_entries(activation)["postgresql"]
    marker = state_path(postgresql_entry)

    failure = switch_postgresql_host(host, label, succeed=False)
    assert failure, (fault, failure)
    interrupted = read_json(marker)
    details = interrupted["details"]
    assert details["phase"] == expected_phase, (fault, details)
    fault_marker = f"{details['cluster_root']}/.fault-fired-{fault}"
    assert_protected_file(fault_marker, details["uid"], 71, "600")
    expected_fault_marker = (
        f"{fault}|"
        f"{details['postgres_executable'].removesuffix('/bin/postgres')}|"
        f"{details['configuration_revision']}\n"
    )
    assert runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(fault_marker)}"
    ) == expected_fault_marker
    fault_marker_snapshot = runtime.succeed(
        f"{COREUTILS}/stat -c '%i|%u|%g|%a|%s|%Y|%Z' "
        f"{shlex.quote(fault_marker)} && "
        f"{COREUTILS}/sha256sum {shlex.quote(fault_marker)}"
    )

    generation = switch_postgresql_host(host, label + "-recover")
    transaction, _, _, _ = assert_single_postgresql_reconciliation(
        generation,
        activation,
        expected_method,
    )
    states = resource_states(activation)
    recovered = assert_cluster_layout(states)
    assert_candidate_publication(recovered)
    assert_process_boundary(recovered)
    secret = output + "/test-only/credential.secret"
    assert_sql_ready(recovered, secret)
    assert runtime.succeed(
        f"{COREUTILS}/stat -c '%i|%u|%g|%a|%s|%Y|%Z' "
        f"{shlex.quote(fault_marker)} && "
        f"{COREUTILS}/sha256sum {shlex.quote(fault_marker)}"
    ) == fault_marker_snapshot
    secret_text = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(secret)}"
    ).rstrip("\n")
    assert_runtime_redaction(generation, transaction, [secret_text])
    return activation, states, recovered, secret


fault_cases = [
    (
        "crash-initdb-before-pg-version",
        "fault_before_database",
        "fault_before_role",
        "sha256:" + "61" * 32,
        "preparing",
        "materialize",
    ),
    (
        "crash-initdb-after-pg-version",
        "fault_after_database",
        "fault_after_role",
        "sha256:" + "62" * 32,
        "preparing",
        "materialize",
    ),
    (
        "crash-quarantine-config",
        "fault_after_database",
        "fault_after_role",
        "sha256:" + "63" * 32,
        "quarantinestarting",
        "restart",
    ),
    (
        "crash-quarantine-hba",
        "fault_after_database",
        "fault_after_role",
        "sha256:" + "64" * 32,
        "quarantinestarting",
        "restart",
    ),
    (
        "crash-quarantine-ident",
        "fault_after_database",
        "fault_after_role",
        "sha256:" + "65" * 32,
        "quarantinestarting",
        "restart",
    ),
    (
        "crash-publish-final-config",
        "fault_after_database",
        "fault_after_role",
        "sha256:" + "66" * 32,
        "publishingfinal",
        "restart",
    ),
    (
        "crash-publish-final-hba",
        "fault_after_database",
        "fault_after_role",
        "sha256:" + "67" * 32,
        "publishingfinal",
        "restart",
    ),
    (
        "crash-publish-final-ident",
        "fault_after_database",
        "fault_after_role",
        "sha256:" + "68" * 32,
        "publishingfinal",
        "restart",
    ),
]

fault_results = []
for fault_index, fault_case in enumerate(fault_cases, start=1):
    fault_results.append(run_postgresql_fault(fault_index, *fault_case))

activation_fault_final, states_fault_final, details_fault_final, secret_fault_final = (
    fault_results[-1]
)
