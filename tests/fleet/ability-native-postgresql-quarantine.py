# Live quarantine keeps public brokers unprivileged while repair remains possible.
activation_hold = generate_postgresql_activation(
    "/run/postgresql-hold",
    "ability_app",
    "ability_role",
    "sha256:" + "33" * 32,
    "postgresql-hold",
    "/run/postgresql-authority-hold",
    fault="hold-quarantine-after-start",
)
provision_postgresql_authority(
    activation_hold,
    "/run/postgresql-authority-hold",
)
hold_host = "/run/postgresql-host-hold.nix"
write_postgresql_host(hold_host, activation_hold)
hold_entries = resource_entries(activation_hold)
hold_postgresql_state_path = state_path(hold_entries["postgresql"])
secret_hold = "/run/postgresql-hold/test-only/credential.secret"

hold_release = "/run/aos-postgresql-quarantine-hold-release"
hold_status = "/run/postgresql-quarantine-hold.status"
hold_log = "/run/postgresql-quarantine-hold.log"
runtime.succeed(
    f"{COREUTILS}/rm -f {hold_release} {hold_status} {hold_log}; "
    "( set +e; "
    f"{APM} switch --from {hold_host} "
    "--eval-root /run/postgresql-eval-quarantine-hold; "
    f"status=$?; printf '%s\\n' \"$status\" > {hold_status} ) "
    f"> {hold_log} 2>&1 < /dev/null &"
)

runtime.wait_until_succeeds(
    f"{JQ} -e '.details.phase == \"quarantinestarting\"' "
    f"{shlex.quote(hold_postgresql_state_path)}",
    timeout=1200,
)
states_hold_live = resource_states(activation_hold)
details_hold_live = states_hold_live["postgresql"]["details"]
endpoint_hold_details = states_hold_live["network-endpoint"]["details"]
assert details_hold_live["process"] is None, details_hold_live

probe_drop = (
    f"{SETPRIV} --reuid={details_hold_live['probe_uid']} "
    f"--regid={details_hold_live['probe_gid']} --clear-groups "
    "--no-new-privs --inh-caps=-all --ambient-caps=-all "
    "--bounding-set=-all"
)
runtime.wait_until_succeeds(
    f"{probe_drop} {PG_ISREADY} -h {details_hold_live['run_path']} "
    f"-p {details_hold_live['server_port']} -t 1",
    timeout=1200,
)
runtime.succeed(
    f"{COREUTILS}/cmp -s {details_hold_live['active_hba_path']} "
    f"{details_hold_live['quarantine_hba_path']}"
)
runtime.succeed(
    f"{COREUTILS}/cmp -s {details_hold_live['active_ident_path']} "
    f"{details_hold_live['quarantine_ident_path']}"
)
assert_broker_process(
    endpoint_hold_details["brokers"]["ipv4"],
    endpoint_hold_details["ipv4_identity"],
    "ipv4",
)
assert_broker_process(
    endpoint_hold_details["brokers"]["ipv6"],
    endpoint_hold_details["ipv6_identity"],
    "ipv6",
)

for address in ("127.0.0.1", "::1"):
    for role in ("aos-ability-postgresql", details_hold_live["role"]):
        database = (
            "postgres"
            if role == "aos-ability-postgresql"
            else details_hold_live["database"]
        )
        password = (
            ""
            if role == "aos-ability-postgresql"
            else f"{COREUTILS}/cat {shlex.quote(secret_hold)} | "
        )
        prompt = "" if role == "aos-ability-postgresql" else "-W "
        runtime.fail(
            f"{password}{COREUTILS}/timeout 5 {PSQL} -X --no-psqlrc {prompt}"
            "--set ON_ERROR_STOP=1 "
            f"-h {shlex.quote(address)} "
            f"-p {details_hold_live['endpoint']['port']} "
            f"-U {shlex.quote(role)} -d {shlex.quote(database)} "
            "-c 'SELECT 1'",
            timeout=10,
        )

runtime.succeed(
    f"{COREUTILS}/install -o root -g root -m 0600 /dev/null {hold_release}"
)
runtime.wait_until_succeeds(
    f"test -s {hold_status}",
    timeout=1200,
)
assert runtime.succeed(f"{COREUTILS}/cat {hold_status}").strip() == "0", (
    runtime.succeed(f"{COREUTILS}/cat {hold_log}"),
)

generation_hold = current_generation()
transaction_hold, _, _ = assert_effect_graph(
    generation_hold,
    activation_hold,
    update_operations,
    10,
)
states_hold = resource_states(activation_hold)
details_hold = assert_cluster_layout(states_hold)
secret_text_hold = runtime.succeed(
    f"{COREUTILS}/cat {shlex.quote(secret_hold)}"
).rstrip("\n")
assert_sql_ready(details_hold, secret_hold)
assert_runtime_redaction(
    generation_hold,
    transaction_hold,
    [secret_text_v1, secret_text_v2, secret_text_hold],
)
