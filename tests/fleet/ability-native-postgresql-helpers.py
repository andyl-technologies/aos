# Shared physical-state, graph, SQL, and security assertions.
RUNTIME_ROOT = "/var/lib/aos/ability-runtime"


def canonical_digest(domain, value):
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(domain.encode() + b"\0" + payload).hexdigest()


def resource_digest(resource):
    return canonical_digest(
        "aos.ability.native-host-resource/v1",
        resource,
    )


def resource_entries(activation):
    entries = native_resource_map(activation)["entries"]
    assert len(entries) == 5, entries
    by_kind = {
        entry["qualification"]["kind"]: entry
        for entry in entries
    }
    assert set(by_kind) == {
        "credential-delivery",
        "host-network-policy",
        "host-storage",
        "network-endpoint",
        "postgresql",
    }, by_kind
    return by_kind


def state_path(entry):
    digest = resource_digest(entry["resource"])
    kind = entry["qualification"]["kind"]
    if kind == "credential-delivery":
        return f"{RUNTIME_ROOT}/credentials/.{digest}.json"
    if kind == "host-storage":
        return f"{RUNTIME_ROOT}/storage/.{digest}.json"
    if kind == "postgresql":
        return f"{RUNTIME_ROOT}/postgresql/.{digest}.json"
    if kind == "network-endpoint":
        return f"{RUNTIME_ROOT}/endpoints/{digest}.json"
    if kind == "host-network-policy":
        return f"{RUNTIME_ROOT}/network-policy/{digest}.json"
    raise AssertionError(kind)


def read_json(path):
    return json.loads(runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(path)}"
    ))


def resource_states(activation):
    return {
        kind: read_json(state_path(entry))
        for kind, entry in resource_entries(activation).items()
    }


def all_runtime_states(kind):
    directories = {
        "credential-delivery": "credentials",
        "host-network-policy": "network-policy",
        "host-storage": "storage",
        "network-endpoint": "endpoints",
        "postgresql": "postgresql",
    }
    root = f"{RUNTIME_ROOT}/{directories[kind]}"
    paths = runtime.succeed(
        f"{FIND} {shlex.quote(root)} -mindepth 1 -maxdepth 1 "
        "-type f -name '.*.json' -print"
    ).splitlines()
    states = [read_json(path) for path in paths]
    for state in states:
        assert state["qualification"]["kind"] == kind, state
    return states


def postgresql_states_by_cluster():
    states = all_runtime_states("postgresql")
    result = {
        state["details"]["cluster"]: state
        for state in states
    }
    assert len(result) == len(states), states
    return result


def transaction_document(generation):
    activation_record = read_json(
        f"/var/lib/profiles/system/gen-{generation}/activation.json"
    )
    transaction = activation_record["native_ability_transaction"]
    root = (
        f"/var/lib/profiles/system/gen-{generation}/"
        f"ability-transactions/{transaction}"
    )
    bundle = read_json(f"{root}/plan-bundle.json")
    terminal = read_json(f"{root}/terminal.json")
    journal = f"{root}/execution.journal"
    assert terminal["transaction"] == transaction, terminal
    assert terminal["terminal"] == "complete", terminal
    runtime.succeed(f"test -s {shlex.quote(journal)}")
    return transaction, root, bundle, terminal


def assert_successful_transaction(generation, transaction, root, bundle):
    journal = f"{root}/execution.journal"
    journal_text = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(journal)}"
    )
    events = [
        json.loads(line)
        for line in journal_text.splitlines()
        if line.strip()
    ]
    assert events, journal_text

    digest_before = runtime.succeed(
        f"{COREUTILS}/sha256sum {shlex.quote(journal)}"
    ).split()[0]
    diagnostic = json.loads(runtime.succeed(
        f"{AOS} --json ability diagnostic "
        f"{shlex.quote(f'/var/lib/profiles/system/gen-{generation}')} "
        f"{shlex.quote(transaction)}"
    ))
    digest_after = runtime.succeed(
        f"{COREUTILS}/sha256sum {shlex.quote(journal)}"
    ).split()[0]
    assert digest_after == digest_before, (digest_before, digest_after)
    assert diagnostic["schema"] == "aos.ability.diagnostic-bundle/v1", diagnostic
    assert diagnostic["audience"] == "redacted", diagnostic
    assert diagnostic["inputs"]["disclosure"] == "redacted", diagnostic
    assert diagnostic["plan"] == bundle["plan"], (diagnostic, bundle)
    assert diagnostic["timeline"]["plan"] == bundle["plan"], diagnostic

    operations = bundle["transition"]["effect_document"]["operations"]
    completed = {
        event["node_ordinal"]
        for event in diagnostic["timeline"]["events"]
        if event["kind"] == "effect-completed"
    }
    assert set(range(len(operations))) <= completed, (completed, operations)


def assert_single_postgresql_reconciliation(
    generation,
    activation,
    expected_method,
):
    transaction, root, bundle, terminal = transaction_document(generation)
    entries = native_resource_map(activation)["entries"]
    postgresql_resources = {
        json.dumps(entry["resource"], sort_keys=True)
        for entry in entries
        if entry["qualification"]["kind"] == "postgresql"
    }
    operations = bundle["transition"]["effect_document"]["operations"]
    ordinals = [
        ordinal
        for ordinal, operation in enumerate(operations)
        if operation["method"] == expected_method
        and json.dumps(operation["target"]["resource"], sort_keys=True)
        in postgresql_resources
    ]
    assert len(ordinals) == 1, (ordinals, operations)
    ordinal = ordinals[0]

    diagnostic = json.loads(runtime.succeed(
        f"{AOS} --json ability diagnostic "
        f"{shlex.quote(f'/var/lib/profiles/system/gen-{generation}')} "
        f"{shlex.quote(transaction)}"
    ))
    events = [
        event
        for event in diagnostic["timeline"]["events"]
        if event.get("node_ordinal") == ordinal
    ]
    kinds = [event["kind"] for event in events]
    assert kinds.count("effect-started") == 1, (kinds, diagnostic)
    assert kinds.count("effect-completed") == 0, (kinds, diagnostic)
    assert kinds.count("reconciliation-started") == 1, (kinds, diagnostic)
    assert kinds.count("reconciled-completed") == 1, (kinds, diagnostic)
    assert terminal["plan"] == bundle["plan"], (terminal, bundle)
    return transaction, root, bundle, ordinal


def assert_effect_graph(
    generation,
    activation,
    expected,
    edge_count,
    resource_activation=None,
):
    transaction, root, bundle, terminal = transaction_document(generation)
    effect = bundle["transition"]["effect_document"]
    if resource_activation is None:
        resource_activation = activation
    entries = native_resource_map(resource_activation)["entries"]
    kind_by_resource = {
        json.dumps(entry["resource"], sort_keys=True):
            entry["qualification"]["kind"]
        for entry in entries
    }
    observed = {
        (
            kind_by_resource[
                json.dumps(
                    operation["target"]["resource"],
                    sort_keys=True,
                )
            ],
            operation["method"],
        )
        for operation in effect["operations"]
    }
    assert observed == set(expected), (observed, expected, effect)
    assert len(effect["operations"]) == len(expected), effect
    assert len(effect["edges"]) == edge_count, effect
    assert terminal["plan"] == bundle["plan"], (terminal, bundle)
    assert_successful_transaction(generation, transaction, root, bundle)
    return transaction, root, bundle


def assert_required_edge(
    bundle,
    activation,
    before,
    after,
    resource_activation=None,
):
    effect = bundle["transition"]["effect_document"]
    if resource_activation is None:
        resource_activation = activation
    entries = native_resource_map(resource_activation)["entries"]
    kind_by_resource = {
        json.dumps(entry["resource"], sort_keys=True):
            entry["qualification"]["kind"]
        for entry in entries
    }
    operation_keys = {
        (
            kind_by_resource[
                json.dumps(
                    operation["target"]["resource"],
                    sort_keys=True,
                )
            ],
            operation["method"],
        ): operation["key"]["key"]
        for operation in effect["operations"]
    }
    expected = (
        operation_keys[before],
        operation_keys[after],
        "required-success",
    )
    observed = {
        (
            edge["from"]["key"]["key"],
            edge["to"]["key"]["key"],
            edge["kind"],
        )
        for edge in effect["edges"]
    }
    assert expected in observed, (expected, observed)


def assert_root_layout():
    expected = {
        RUNTIME_ROOT: (0, 71, "710"),
        f"{RUNTIME_ROOT}/credential-sources": (0, 0, "700"),
        f"{RUNTIME_ROOT}/credentials": (0, 0, "700"),
        f"{RUNTIME_ROOT}/endpoints": (0, 0, "700"),
        f"{RUNTIME_ROOT}/network-policy": (0, 0, "700"),
        f"{RUNTIME_ROOT}/storage": (0, 71, "710"),
        f"{RUNTIME_ROOT}/postgresql": (0, 71, "710"),
        "/run/aos-ability-postgresql": (0, 0, "711"),
    }
    for path, identity in expected.items():
        observed = runtime.succeed(
            f"{COREUTILS}/stat -c '%u %g %a' {shlex.quote(path)}"
        ).strip()
        assert observed == " ".join(map(str, identity)), (
            path,
            observed,
            identity,
        )


def assert_slot_accounts():
    passwd = runtime.succeed(f"{COREUTILS}/cat /etc/passwd")
    groups = runtime.succeed(f"{COREUTILS}/cat /etc/group")
    observed_ids = set()
    for slot in range(64):
        suffix = f"{slot:02d}"
        server = f"aos-ability-pg-{suffix}"
        probe = f"aos-ability-pg-probe-{suffix}"
        broker = f"aos-ability-pg-broker-{suffix}"
        server_uid = 7100 + slot
        probe_id = 7200 + slot
        broker_uid = 7300 + slot
        assert (
            f"{server}:x:{server_uid}:71:" in passwd
        ), (server, passwd)
        assert (
            f"{probe}:x:{probe_id}:{probe_id}:" in passwd
        ), (probe, passwd)
        assert (
            f"{broker}:x:{broker_uid}:{probe_id}:" in passwd
        ), (broker, passwd)
        assert f"{probe}:x:{probe_id}:" in groups, (probe, groups)
        socket_identity = runtime.succeed(
            f"{COREUTILS}/stat -c '%u %g %a' "
            f"/run/aos-ability-postgresql/{suffix}"
        ).strip()
        assert socket_identity == f"{server_uid} {probe_id} 2710", (
            suffix,
            socket_identity,
        )
        observed_ids.update((server_uid, probe_id, broker_uid))
    assert len(observed_ids) == 192, observed_ids


def assert_protected_file(path, uid, gid, mode, allow_empty=False):
    fields = runtime.succeed(
        f"{COREUTILS}/stat -c '%F|%u|%g|%a|%h|%s' "
        f"{shlex.quote(path)}"
    ).strip().split("|")
    assert fields[0] == "regular file", (path, fields)
    assert fields[1:5] == [str(uid), str(gid), mode, "1"], (
        path,
        fields,
    )
    if not allow_empty:
        assert int(fields[5]) > 0, (path, fields)


def assert_cluster_layout(states):
    postgresql = states["postgresql"]
    storage = states["host-storage"]
    credential = states["credential-delivery"]
    details = postgresql["details"]
    slot = details["slot"]
    suffix = f"{slot:02d}"
    digest = resource_digest(postgresql["resource"])
    storage_digest = resource_digest(storage["resource"])

    assert set(postgresql) == {
        "schema",
        "resource",
        "revision",
        "qualification",
        "details",
    }, postgresql
    assert details["phase"] == "active", details
    assert details["auth"] == "scram", details
    assert details["prior_active"] is None, details
    assert details["role_verifier_digest"].startswith("sha256:"), details
    assert details["credential"]["resource"] == credential["resource"], details

    assert details["uid"] == 7100 + slot, details
    assert details["gid"] == 71, details
    assert details["principal"] == f"aos-ability-pg-{suffix}", details
    assert details["probe_uid"] == 7200 + slot, details
    assert details["probe_gid"] == 7200 + slot, details
    assert details["probe_principal"] == (
        f"aos-ability-pg-probe-{suffix}"
    ), details
    assert details["cluster_root"] == (
        f"{RUNTIME_ROOT}/postgresql/{digest}"
    ), details
    assert details["storage_path"] == (
        f"{RUNTIME_ROOT}/storage/{storage_digest}"
    ), details
    assert details["data_path"] == details["storage_path"] + "/data"
    assert details["run_path"] == (
        f"/run/aos-ability-postgresql/{suffix}"
    ), details

    for path in (details["cluster_root"], details["storage_path"], details["data_path"]):
        assert runtime.succeed(
            f"{COREUTILS}/stat -c '%u %g %a' {shlex.quote(path)}"
        ).strip() == f"{details['uid']} 71 700", path
    assert runtime.succeed(
        f"{COREUTILS}/stat -c '%u %g %a' "
        f"{shlex.quote(details['run_path'])}"
    ).strip() == f"{details['uid']} {details['probe_gid']} 2710"

    for key in (
        "active_config_path",
        "active_hba_path",
        "active_ident_path",
        "final_config_path",
        "final_hba_path",
        "final_ident_path",
        "quarantine_config_path",
        "quarantine_hba_path",
        "quarantine_ident_path",
    ):
        assert_protected_file(
            details[key],
            details["uid"],
            71,
            "600",
            allow_empty=False,
        )

    for path_key, digest_key in (
        ("active_config_path", "final_config_digest"),
        ("active_hba_path", "final_hba_digest"),
        ("active_ident_path", "final_ident_digest"),
        ("final_config_path", "final_config_digest"),
        ("final_hba_path", "final_hba_digest"),
        ("final_ident_path", "final_ident_digest"),
        ("quarantine_config_path", "quarantine_config_digest"),
        ("quarantine_hba_path", "quarantine_hba_digest"),
        ("quarantine_ident_path", "quarantine_ident_digest"),
    ):
        observed_digest = runtime.succeed(
            f"{COREUTILS}/sha256sum {shlex.quote(details[path_key])}"
        ).split()[0]
        assert details[digest_key] == f"sha256:{observed_digest}", (
            path_key,
            digest_key,
            details,
        )

    assert_protected_file(
        state_path(resource_entries_from_states(states)["postgresql"]),
        0,
        0,
        "600",
    )
    assert_protected_file(
        credential["details"]["view_path"],
        0,
        0,
        "400",
    )
    for kind, state in states.items():
        marker = state_path(resource_entries_from_states(states)[kind])
        assert_protected_file(marker, 0, 0, "600")

    return details


def resource_entries_from_states(states):
    # State carries the exact ResourceId and qualification, so this
    # projection is sufficient for canonical physical marker paths.
    return {
        kind: {
            "resource": state["resource"],
            "qualification": state["qualification"],
        }
        for kind, state in states.items()
    }


def assert_candidate_publication(details):
    for active, final in (
        ("active_config_path", "final_config_path"),
        ("active_hba_path", "final_hba_path"),
        ("active_ident_path", "final_ident_path"),
    ):
        runtime.succeed(
            f"{COREUTILS}/cmp -s "
            f"{shlex.quote(details[active])} "
            f"{shlex.quote(details[final])}"
        )

    final_hba = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(details['final_hba_path'])}"
    )
    final_ident = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(details['final_ident_path'])}"
    )
    quarantine_ident = runtime.succeed(
        f"{COREUTILS}/cat {shlex.quote(details['quarantine_ident_path'])}"
    )
    for path in (
        details["active_config_path"],
        details["final_config_path"],
        details["quarantine_config_path"],
    ):
        settings = runtime.succeed(
            f"{COREUTILS}/cat {shlex.quote(path)}"
        ).splitlines()
        assert settings.count("shared_buffers = 8MB") == 1, (path, settings)
        assert settings.count("max_connections = 8") == 1, (path, settings)
    assert final_hba == (
        f'local all "aos-ability-postgresql" peer '
        f'map=aos_slot_{details["slot"]:02d}\n'
        f'local "{details["database"]}" "{details["role"]}" '
        + (
            "scram-sha-256\n"
            if details["auth"] == "scram"
            else "trust\n"
        )
        + "local all all reject\n"
        + "host all all 127.0.0.1/32 reject\n"
        + "host all all ::1/128 reject\n"
    ), final_hba
    assert final_ident == (
        f'aos_slot_{details["slot"]:02d} '
        f'{details["principal"]} aos-ability-postgresql\n'
    ), final_ident
    assert quarantine_ident == (
        f'aos_slot_{details["slot"]:02d} '
        f'{details["probe_principal"]} aos-ability-postgresql\n'
    ), quarantine_ident
    assert admin_psql(
        details,
        "SHOW shared_buffers; SHOW max_connections",
    ) == "8MB\n8"


def psql_query(details, secret_path, database=None, role=None):
    selected_database = database or details["database"]
    selected_role = role or details["role"]
    password = (
        f"{COREUTILS}/cat {shlex.quote(secret_path)} | "
        if secret_path is not None
        else ""
    )
    prompt = "-W " if secret_path is not None else ""
    readiness_sql = (
        "SELECT current_user || '|' || current_database() || '|' "
        "|| current_setting('aos.configuration_revision')"
    )
    return runtime.succeed(
        f"{password}{PSQL} -X --no-psqlrc {prompt}"
        "--no-align --tuples-only --set ON_ERROR_STOP=1 "
        f"-h 127.0.0.1 -p {details['endpoint']['port']} "
        f"-U {shlex.quote(selected_role)} "
        f"-d {shlex.quote(selected_database)} "
        f"-c {shlex.quote(readiness_sql)}",
        timeout=30,
    ).strip()


def assert_sql_ready(details, secret_path):
    observed = psql_query(details, secret_path)
    assert observed == (
        f"{details['role']}|{details['database']}|"
        f"{details['configuration_revision']}"
    ), observed
    for database, role in (
        ("postgres", details["role"]),
        (details["database"], "aos-ability-postgresql"),
        (details["database"], "aos-ability-pg-other"),
        ("template1", details["role"]),
    ):
        password = (
            f"{COREUTILS}/cat {shlex.quote(secret_path)} | "
            if secret_path is not None
            else ""
        )
        prompt = "-W " if secret_path is not None else ""
        runtime.fail(
            f"{password}{COREUTILS}/timeout 5 {PSQL} "
            f"-X --no-psqlrc {prompt}--set ON_ERROR_STOP=1 "
            f"-h 127.0.0.1 -p {details['endpoint']['port']} "
            f"-U {shlex.quote(role)} -d {shlex.quote(database)} "
            "-c 'SELECT 1'",
            timeout=10,
        )


def admin_psql(details, sql, succeed=True):
    command = (
        f"{COREUTILS}/env -i HOME=/var/empty LANG=C LC_ALL=C "
        f"PATH={COREUTILS} TZ=UTC {SETPRIV} "
        f"--reuid={details['uid']} --regid=71 --clear-groups "
        "--no-new-privs --inh-caps=-all --ambient-caps=-all "
        f"--bounding-set=-all {PSQL} -X --no-psqlrc "
        "--no-align --tuples-only --set ON_ERROR_STOP=1 "
        f"-h {shlex.quote(details['run_path'])} "
        f"-p {details['server_port']} "
        "-U aos-ability-postgresql -d postgres "
        f"-c {shlex.quote(sql)}"
    )
    if succeed:
        return runtime.succeed(command, timeout=30).strip()
    runtime.fail(command, timeout=30)
    return None


def application_psql(details, secret_path, sql, succeed=True):
    password = (
        f"{COREUTILS}/cat {shlex.quote(secret_path)} | "
        if secret_path is not None
        else ""
    )
    prompt = "-W " if secret_path is not None else ""
    command = (
        f"{password}{PSQL} -X --no-psqlrc {prompt}"
        "--no-align --tuples-only --set ON_ERROR_STOP=1 "
        f"-h 127.0.0.1 -p {details['endpoint']['port']} "
        f"-U {shlex.quote(details['role'])} "
        f"-d {shlex.quote(details['database'])} "
        f"-c {shlex.quote(sql)}"
    )
    if succeed:
        return runtime.succeed(command, timeout=30).strip()
    runtime.fail(command, timeout=30)
    return None


def assert_runtime_redaction(generation, transaction, secrets):
    roots = [
        f"/var/lib/profiles/system/gen-{generation}/ability-transactions/{transaction}",
        f"/var/lib/profiles/system/gen-{generation}/activation.json",
        f"{RUNTIME_ROOT}/postgresql",
    ]
    for secret in secrets:
        for root in roots:
            runtime.fail(
                f"{GREP} -R -F -- {shlex.quote(secret)} {shlex.quote(root)}",
                timeout=30,
            )


def postmaster_identity(details):
    pid = runtime.succeed(
        f"{COREUTILS}/head -n 1 "
        f"{shlex.quote(details['data_path'] + '/postmaster.pid')}"
    ).strip()
    executable = runtime.succeed(
        f"{COREUTILS}/readlink /proc/{pid}/exe"
    ).strip()
    return pid, executable


def assert_process_boundary(details):
    pid, executable = postmaster_identity(details)
    process = details["process"]
    assert process["schema"] == "aos.postgresql.control-process/v1", process
    assert process["pid"] == int(pid), process
    assert process["executable"] == details["postgres_executable"], process
    assert process["uid"] == details["uid"], process
    assert process["gid"] == 71, process
    assert process["groups"] == [], process
    assert process["no_new_privileges"] is True, process
    assert set(process["capabilities"]) == {
        "inheritable",
        "permitted",
        "effective",
        "bounding",
        "ambient",
    }, process
    assert set(process["capabilities"].values()) == {
        "0000000000000000"
    }, process
    assert process["arguments"] == [
        details["postgres_executable"],
        "-D",
        details["data_path"],
        "-c",
        f"config_file={details['active_config_path']}",
    ], process
    boot_id = runtime.succeed(
        f"{COREUTILS}/cat /proc/sys/kernel/random/boot_id"
    ).strip()
    assert process["boot_id"] == boot_id, process
    stat_suffix = runtime.succeed(
        f"{COREUTILS}/cat /proc/{pid}/stat"
    ).rsplit(") ", 1)[1].split()
    assert process["process_group"] == int(stat_suffix[2]), process
    assert process["process_group"] == int(pid), process
    assert int(stat_suffix[3]) == int(pid), stat_suffix
    assert process["start_time"] == int(stat_suffix[19]), process
    argv = runtime.succeed(
        f"{COREUTILS}/od -An -v -tx1 /proc/{pid}/cmdline"
    ).split()
    assert "".join(argv) == (
        "\0".join(process["arguments"]) + "\0"
    ).encode().hex(), process
    status = runtime.succeed(
        f"{COREUTILS}/cat /proc/{pid}/status"
    ).splitlines()
    fields = {
        line.split(":", 1)[0]: line.split(":", 1)[1].split()
        for line in status
        if ":" in line
    }
    assert fields["Uid"] == [str(details["uid"])] * 4, fields
    assert fields["Gid"] == ["71"] * 4, fields
    assert fields["Groups"] == [], fields
    assert fields["NoNewPrivs"] == ["1"], fields
    for capability in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert fields[capability] == ["0000000000000000"], fields
    assert executable == details["postgres_executable"], (
        executable,
        details,
    )


def assert_identity_isolation(details, credential_view):
    sibling_slot = (details["slot"] + 1) % 64
    sibling_probe = 7200 + sibling_slot
    drop = (
        f"{SETPRIV} --reuid={sibling_probe} --regid={sibling_probe} "
        "--clear-groups --no-new-privs --inh-caps=-all "
        "--ambient-caps=-all --bounding-set=-all"
    )
    runtime.fail(
        f"{drop} {COREUTILS}/cat {shlex.quote(credential_view)}"
    )
    runtime.fail(
        f"{drop} {PSQL} -X --no-psqlrc --set ON_ERROR_STOP=1 "
        f"-h {shlex.quote(details['run_path'])} "
        f"-p {details['server_port']} -U aos-ability-postgresql "
        "-d postgres -c 'SELECT 1'",
        timeout=30,
    )


def assert_root_control_rejected(details, qualification):
    control = qualification["control"]["store_path"] + "/bin/postgresql-control"
    postgresql = qualification["postgresql"]["store_path"]
    process = details["process"]
    identity = (
        "--slot", f"{details['slot']:02d}",
        "--postgresql-artifact", postgresql,
        "--port", str(details["server_port"]),
        "--configuration-revision", details["configuration_revision"],
        "--database", details["database"],
        "--role", details["role"],
        "--auth", details["auth"],
    )
    server_paths = (
        "--data-directory", details["data_path"],
        "--cluster-directory", details["cluster_root"],
        "--run-directory", details["run_path"],
        "--expected-boot-id", process["boot_id"],
        "--expected-pid", str(process["pid"]),
        "--expected-process-group", str(process["process_group"]),
        "--expected-start-time", str(process["start_time"]),
    )
    invocations = [
        (mode, identity + server_paths)
        for mode in (
            "prepare",
            "authenticate-active",
            "authenticate-stop",
            "publish-final",
            "start-final",
            "stop",
        )
    ]
    invocations.extend((
        (
            "quarantine-start",
            identity + server_paths + (
                "--prior-config-digest", details["final_config_digest"],
                "--prior-hba-digest", details["final_hba_digest"],
                "--prior-ident-digest", details["final_ident_digest"],
            ),
        ),
        (
            "repair",
            identity + ("--run-directory", details["run_path"]),
        ),
        (
            "observe",
            identity + ("--address", "127.0.0.1"),
        ),
    ))
    for mode, arguments in invocations:
        command = " ".join(
            shlex.quote(value)
            for value in (control, mode, *arguments)
        )
        output = runtime.succeed(
            "set +e; "
            f"output=$({command} 2>&1); status=$?; "
            "test \"$status\" -eq 65; printf '%s' \"$output\""
        )
        assert "wrong permanent identity" in output, (mode, output)


def assert_package_closure_boundary():
    runtime.fail(
        f"{NIX_STORE} -qR {shlex.quote(PACKAGE_RUNTIME)} "
        f"| {GREP} -E '/nix/store/[^/]+-postgresql-[0-9]'"
    )
    baseline = next(
        entry
        for entry in REFERENCE_PACKAGES
        if entry["name"] == "ability-reference-postgresql"
    )
    runtime.succeed(
        f"{NIX_STORE} -qR {shlex.quote(baseline['package'])} "
        f"| {GREP} -E '/nix/store/[^/]+-postgresql-[0-9]'"
    )


def protected_snapshot(states, details):
    paths = [
        state_path(entry)
        for entry in resource_entries_from_states(states).values()
    ]
    paths.extend(
        details[key]
        for key in (
            "active_config_path",
            "active_hba_path",
            "active_ident_path",
            "final_config_path",
            "final_hba_path",
            "final_ident_path",
            "quarantine_config_path",
            "quarantine_hba_path",
            "quarantine_ident_path",
        )
    )
    files = {
        path: runtime.succeed(
            f"{COREUTILS}/stat -c '%i|%u|%g|%a|%s|%Y|%Z' "
            f"{shlex.quote(path)}"
            f" && {COREUTILS}/sha256sum {shlex.quote(path)}"
        )
        for path in paths
    }
    policy = states["host-network-policy"]["details"]
    ruleset = runtime.succeed(
        f"{NFT} -j -a list table inet {shlex.quote(policy['table'])}"
    )
    return {
        "files": files,
        "postmaster": postmaster_identity(details),
        "ruleset": ruleset,
    }
