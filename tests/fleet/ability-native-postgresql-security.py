# Candidate, active-state, and authority tampering must fail before stopping SQL.


def replace_protected_text(path, text, uid, gid, mode):
    encoded = base64.b64encode(text.encode()).decode()
    directory = path.rsplit("/", 1)[0]
    temporary = path + ".acceptance-restore"
    runtime.succeed(textwrap.dedent(f"""
        set -eu
        printf '%s' {shlex.quote(encoded)} | {COREUTILS}/base64 -d > {shlex.quote(temporary)}
        {COREUTILS}/chown {uid}:{gid} {shlex.quote(temporary)}
        {COREUTILS}/chmod {mode} {shlex.quote(temporary)}
        {COREUTILS}/sync -d {shlex.quote(temporary)}
        {COREUTILS}/mv -T {shlex.quote(temporary)} {shlex.quote(path)}
        {COREUTILS}/sync -f {shlex.quote(directory)}
    """))


def reject_tamper_and_recover(label, path, tampered_text, uid, gid, mode):
    original = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(path)}"
    )
    process_before = details_hold["process"]
    pid_before = postmaster_identity(details_hold)
    generation_before = current_generation()

    replace_protected_text(path, tampered_text, uid, gid, mode)
    host = f"/run/postgresql-host-tamper-{label}.nix"
    write_postgresql_host(host, activation_hold)
    switch_postgresql_host(host, f"tamper-{label}", succeed=False)
    assert current_generation() == generation_before
    assert postmaster_identity(details_hold) == pid_before
    assert_sql_ready(details_hold, secret_hold)

    replace_protected_text(path, original, uid, gid, mode)
    generation = switch_postgresql_host(host, f"recover-{label}")
    transaction, _, _ = assert_effect_graph(
        generation,
        activation_hold,
        noop_operations,
        5,
    )
    recovered = resource_states(activation_hold)["postgresql"]["details"]
    assert recovered["process"] == process_before, (recovered, process_before)
    assert postmaster_identity(recovered) == pid_before
    assert_sql_ready(recovered, secret_hold)
    assert_runtime_redaction(
        generation,
        transaction,
        [secret_text_v1, secret_text_v2, secret_text_hold],
    )


# The control independently fences every pinned PostgreSQL process that names
# its protected data directory. A constructor-held process makes the exact
# executable observable before PostgreSQL can reject the deliberately invalid
# launch identity or selector.
def start_held_postgres(label, uid, gid, arguments):
    pid_path = f"/run/postgresql-held-{label}.pid"
    log_path = f"/run/postgresql-held-{label}.log"
    argument_text = " ".join(shlex.quote(argument) for argument in arguments)
    drop = (
        f"{SETPRIV} --reuid={uid} --regid={gid} --clear-groups "
        "--no-new-privs --inh-caps=-all --ambient-caps=-all "
        "--bounding-set=-all"
    )
    runtime.succeed(
        f"{COREUTILS}/rm -f {pid_path} {log_path}; "
        f"{drop} {COREUTILS}/env "
        f"LD_PRELOAD={shlex.quote(STOPPED_POSTGRESQL_PRELOAD)} "
        f"{shlex.quote(details_hold['postgres_executable'])} "
        f"{argument_text} > {log_path} 2>&1 < /dev/null & "
        f"printf '%s\\n' $! > {pid_path}"
    )
    runtime.wait_until_succeeds(
        f"pid=$({COREUTILS}/cat {pid_path}); "
        f"test \"$({COREUTILS}/readlink /proc/$pid/exe)\" "
        f"= {shlex.quote(details_hold['postgres_executable'])}; "
        f"{GREP} -Eq '^State:[[:space:]]+T' /proc/$pid/status",
        timeout=30,
    )
    return int(runtime.succeed(f"{COREUTILS}/cat {pid_path}").strip())


def authenticate_active_control_failure():
    qualification = states_hold["postgresql"]["qualification"]
    control = qualification["control"]["store_path"] + "/bin/postgresql-control"
    process = details_hold["process"]
    arguments = (
        "authenticate-active",
        "--slot",
        f"{details_hold['slot']:02d}",
        "--postgresql-artifact",
        qualification["postgresql"]["store_path"],
        "--data-directory",
        details_hold["data_path"],
        "--cluster-directory",
        details_hold["cluster_root"],
        "--run-directory",
        details_hold["run_path"],
        "--port",
        str(details_hold["server_port"]),
        "--configuration-revision",
        details_hold["configuration_revision"],
        "--database",
        details_hold["database"],
        "--role",
        details_hold["role"],
        "--auth",
        details_hold["auth"],
        "--expected-boot-id",
        process["boot_id"],
        "--expected-pid",
        str(process["pid"]),
        "--expected-process-group",
        str(process["process_group"]),
        "--expected-start-time",
        str(process["start_time"]),
    )
    command = " ".join(
        shlex.quote(argument)
        for argument in (control, *arguments)
    )
    server_drop = (
        f"{SETPRIV} --reuid={details_hold['uid']} --regid=71 "
        "--clear-groups --no-new-privs --inh-caps=-all "
        "--ambient-caps=-all --bounding-set=-all"
    )
    return runtime.fail(f"{server_drop} {command}", timeout=30)


wrong_uid_selectors = (
    ("short-separated", ["-D", details_hold["data_path"]]),
    ("short-compact", [f"-D{details_hold['data_path']}"]),
    ("pgdata-separated", ["--pgdata", details_hold["data_path"]]),
    ("pgdata-compact", [f"--pgdata={details_hold['data_path']}"]),
    ("long-separated", ["--data-directory", details_hold["data_path"]]),
    ("long-compact", [f"--data-directory={details_hold['data_path']}"]),
    ("underscore-separated", ["--data_directory", details_hold["data_path"]]),
    ("underscore-compact", [f"--data_directory={details_hold['data_path']}"]),
    ("setting-separated", ["-c", f"data_directory={details_hold['data_path']}"]),
    ("setting-compact", [f"-cdata_directory={details_hold['data_path']}"]),
    ("standalone", ["--version", details_hold["data_path"]]),
)
for selector_label, selector_arguments in wrong_uid_selectors:
    wrong_uid_pid = start_held_postgres(
        f"wrong-uid-{selector_label}",
        details_hold["probe_uid"],
        details_hold["probe_gid"],
        selector_arguments,
    )
    wrong_uid_failure = authenticate_active_control_failure()
    assert (
        "PostgreSQL target process executable is unreadable" in wrong_uid_failure
        or "PostgreSQL target process has the wrong UID" in wrong_uid_failure
    ), (selector_label, wrong_uid_failure)
    runtime.succeed(f"kill -KILL {wrong_uid_pid}")
    runtime.wait_until_fails(f"kill -0 {wrong_uid_pid}", timeout=30)

malformed_selectors = (
    ("short-missing", ["-D"]),
    ("pgdata-empty", ["--pgdata="]),
    ("long-missing", ["--data-directory"]),
    ("underscore-empty", ["--data_directory="]),
    ("setting-missing", ["-c"]),
    ("setting-no-equals", ["-c", "data_directory"]),
    ("setting-compact-no-equals", ["-cdata_directory"]),
)
for selector_label, selector_arguments in malformed_selectors:
    malformed_selector_pid = start_held_postgres(
        f"malformed-{selector_label}",
        details_hold["uid"],
        71,
        selector_arguments,
    )
    malformed_selector_failure = authenticate_active_control_failure()
    assert (
        "PostgreSQL target process data arguments are malformed"
        in malformed_selector_failure
    ), (selector_label, malformed_selector_failure)
    runtime.succeed(f"kill -KILL {malformed_selector_pid}")
    runtime.wait_until_fails(f"kill -0 {malformed_selector_pid}", timeout=30)
assert_sql_ready(details_hold, secret_hold)


for key in (
    "final_config_path",
    "final_hba_path",
    "final_ident_path",
    "quarantine_config_path",
    "quarantine_hba_path",
    "quarantine_ident_path",
    "active_config_path",
    "active_hba_path",
    "active_ident_path",
):
    path = details_hold[key]
    original = runtime.succeed(f"{COREUTILS}/cat {shlex.quote(path)}")
    reject_tamper_and_recover(
        key.removesuffix("_path").replace("_", "-"),
        path,
        original + "# acceptance tamper\n",
        details_hold["uid"],
        71,
        "0600",
    )


postgresql_marker = state_path(resource_entries(activation_hold)["postgresql"])
original_postgresql_state = read_json(postgresql_marker)


def mutated_postgresql_state(mutator):
    document = json.loads(json.dumps(original_postgresql_state))
    mutator(document)
    return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"


state_mutations = (
    (
        "operation-revision",
        lambda state: state.__setitem__("revision", "sha256:" + "ab" * 32),
    ),
    (
        "resource-id",
        lambda state: state["resource"].__setitem__("key", "forged-postgresql"),
    ),
    (
        "configuration-revision",
        lambda state: state["details"].__setitem__(
            "configuration_revision", "sha256:" + "ac" * 32
        ),
    ),
    (
        "reported-path",
        lambda state: state["details"].__setitem__(
            "active_config_path", "/var/lib/aos/forged-postgresql.conf"
        ),
    ),
    (
        "database",
        lambda state: state["details"].__setitem__("database", "forged_database"),
    ),
    (
        "role",
        lambda state: state["details"].__setitem__("role", "forged_role"),
    ),
    (
        "endpoint",
        lambda state: state["details"]["endpoint"].__setitem__(
            "port", state["details"]["endpoint"]["port"] + 1
        ),
    ),
    (
        "storage-resource",
        lambda state: state["details"]["storage_resource"].__setitem__(
            "key", "forged-storage"
        ),
    ),
    (
        "postgres-executable",
        lambda state: state["details"].__setitem__(
            "postgres_executable", "/nix/store/forged/bin/postgres"
        ),
    ),
    (
        "postgresql-major",
        lambda state: state["details"].__setitem__("postgresql_major", 17),
    ),
    (
        "data-system-identifier",
        lambda state: state["details"].__setitem__(
            "data_system_identifier", "1"
        ),
    ),
    (
        "process-start",
        lambda state: state["details"]["process"].__setitem__(
            "start_time", state["details"]["process"]["start_time"] + 1
        ),
    ),
)
for label, mutator in state_mutations:
    reject_tamper_and_recover(
        f"state-{label}",
        postgresql_marker,
        mutated_postgresql_state(mutator),
        0,
        0,
        "0600",
    )


child_mutations = {
    "credential-delivery": lambda state: state.__setitem__(
        "revision", "sha256:" + "ad" * 32
    ),
    "network-endpoint": lambda state: state.__setitem__(
        "revision", "sha256:" + "ae" * 32
    ),
    "host-storage": lambda state: state.__setitem__(
        "revision", "sha256:" + "af" * 32
    ),
    "host-network-policy": lambda state: state.__setitem__(
        "revision", "sha256:" + "ba" * 32
    ),
}
for kind, mutator in child_mutations.items():
    marker = state_path(resource_entries(activation_hold)[kind])
    state = read_json(marker)
    mutator(state)
    reject_tamper_and_recover(
        f"child-{kind}",
        marker,
        json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n",
        0,
        0,
        "0600",
    )

states_security = resource_states(activation_hold)
details_security = states_security["postgresql"]["details"]
assert_cluster_layout(states_security)
assert_process_boundary(details_security)
assert_sql_ready(details_security, secret_hold)
