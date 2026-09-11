# Dual-stack broker ownership, network enforcement, and concurrency bounds.


def broker_process_count(process_group):
    output = runtime.succeed(textwrap.dedent(f"""
        count=0
        for stat in /proc/[0-9]*/stat; do
            test -r "$stat" || continue
            line=$({COREUTILS}/cat "$stat") || continue
            suffix=${{line##*) }}
            set -- $suffix
            test "$3" = {process_group} || continue
            count=$((count + 1))
        done
        printf '%s\n' "$count"
    """))
    return int(output.strip())


def counter_packets(table, comment):
    document = json.loads(runtime.succeed(
        f"{NFT} -j -a list table inet {shlex.quote(table)}"
    ))
    packets = 0
    for entry in document["nftables"]:
        rule = entry.get("rule")
        if rule is None or rule.get("comment") != comment:
            continue
        for expression in rule.get("expr", []):
            counter = expression.get("counter")
            if isinstance(counter, dict):
                packets += counter["packets"]
    return packets


def assert_broker_process(spec, identity, family):
    assert identity["pid"] == identity["process_group"], identity
    assert identity["start_time"] > 0, identity
    assert identity["socket_inode"] > 0, identity
    expected_listener = (
        f"TCP4-LISTEN:{spec['public_port']},bind=0.0.0.0,reuseaddr,"
        "fork,range=127.0.0.0/8,max-children=32"
        if family == "ipv4"
        else (
            f"TCP6-LISTEN:{spec['public_port']},bind=[::],ipv6only=1,"
            "reuseaddr,fork,range=[::1]/128,max-children=32"
        )
    )
    assert spec["listener_argument"] == expected_listener, spec
    expected_backend = (
        f"UNIX-CONNECT:/run/aos-ability-postgresql/{spec['slot']:02d}/"
        f".s.PGSQL.{spec['server_port']}"
    )
    assert spec["backend_argument"] == expected_backend, spec
    assert spec["backend_path"] == expected_backend.removeprefix("UNIX-CONNECT:")
    assert spec["executable"] == SOCAT, spec
    assert spec["uid"] == 7300 + spec["slot"], spec
    assert spec["gid"] == 7200 + spec["slot"], spec
    assert spec["principal"] == (
        f"aos-ability-pg-broker-{spec['slot']:02d}"
    ), spec
    assert spec["uid"] != 7200 + spec["slot"], spec

    pid = identity["pid"]
    status = runtime.succeed(f"{COREUTILS}/cat /proc/{pid}/status").splitlines()
    fields = {
        line.split(":", 1)[0]: line.split(":", 1)[1].split()
        for line in status
        if ":" in line
    }
    assert fields["Uid"] == [str(spec["uid"])] * 4, fields
    assert fields["Gid"] == [str(spec["gid"])] * 4, fields
    assert fields["Groups"] == [], fields
    assert fields["NoNewPrivs"] == ["1"], fields
    for capability in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert fields[capability] == ["0000000000000000"], fields

    argv_hex = "".join(runtime.succeed(
        f"{COREUTILS}/od -An -v -tx1 /proc/{pid}/cmdline"
    ).split())
    expected_argv = (
        spec["executable"] + "\0" + expected_listener + "\0"
        + expected_backend + "\0"
    ).encode().hex()
    assert argv_hex == expected_argv, (argv_hex, expected_argv)

    table = "/proc/net/tcp" if family == "ipv4" else "/proc/net/tcp6"
    wildcard = "00000000" if family == "ipv4" else "0" * 32
    port_hex = f"{spec['public_port']:04X}"
    listeners = []
    for line in runtime.succeed(f"{COREUTILS}/cat {table}").splitlines()[1:]:
        fields = line.split()
        if (
            fields[1] == f"{wildcard}:{port_hex}"
            and fields[3] == "0A"
            and int(fields[9]) == identity["socket_inode"]
        ):
            listeners.append(fields)
    assert len(listeners) == 1, (family, listeners, identity)


endpoint_state = states_readd["network-endpoint"]
endpoint_details = endpoint_state["details"]
assert endpoint_details["phase"] == "allocated", endpoint_details
assert endpoint_details["endpoint"] == details_readd["endpoint"]
assert set(endpoint_details["brokers"]) == {"ipv4", "ipv6"}
assert_broker_process(
    endpoint_details["brokers"]["ipv4"],
    endpoint_details["ipv4_identity"],
    "ipv4",
)
assert_broker_process(
    endpoint_details["brokers"]["ipv6"],
    endpoint_details["ipv6_identity"],
    "ipv6",
)

public_port = details_readd["endpoint"]["port"]
runtime.fail(
    f"{COREUTILS}/timeout 3 {SOCAT} "
    f"TCP4-LISTEN:{public_port},bind=127.0.0.2,reuseaddr -"
)
runtime.fail(
    f"{COREUTILS}/timeout 3 {SOCAT} "
    f"'TCP6-LISTEN:{public_port},bind=[::1],ipv6only=1,reuseaddr' -"
)

password = f"{COREUTILS}/cat {shlex.quote(secret_readd)} | "
ipv6_sql = runtime.succeed(
    f"{password}{PSQL} -X --no-psqlrc -W --no-align --tuples-only "
    "--set ON_ERROR_STOP=1 "
    f"-h ::1 -p {public_port} -U {shlex.quote(details_readd['role'])} "
    f"-d {shlex.quote(details_readd['database'])} -c 'SELECT current_user'",
    timeout=30,
).strip()
assert ipv6_sql == details_readd["role"], ipv6_sql

policy = states_readd["host-network-policy"]["details"]
addresses = json.loads(runtime.succeed(f"{IP} -j -4 address show"))
ipv4_nonloopback = next(
    address["local"]
    for interface in addresses
    for address in interface.get("addr_info", [])
    if address["family"] == "inet" and not address["local"].startswith("127.")
)
ipv4_before = counter_packets(policy["table"], policy["ipv4_comment"])
runtime.fail(
    f"{COREUTILS}/timeout 3 {SOCAT} - "
    f"TCP4:{ipv4_nonloopback}:{public_port},connect-timeout=2"
)
ipv4_after = counter_packets(policy["table"], policy["ipv4_comment"])
assert ipv4_after > ipv4_before, (ipv4_before, ipv4_after)

runtime.succeed(f"{IP} -6 address add fd00::a05/128 dev lo")
ipv6_before = counter_packets(policy["table"], policy["ipv6_comment"])
runtime.fail(
    f"{COREUTILS}/timeout 3 {SOCAT} - "
    f"'TCP6:[fd00::a05]:{public_port},connect-timeout=2'"
)
ipv6_after = counter_packets(policy["table"], policy["ipv6_comment"])
assert ipv6_after > ipv6_before, (ipv6_before, ipv6_after)
runtime.succeed(f"{IP} -6 address del fd00::a05/128 dev lo")

pressure_pid_file = "/run/postgresql-broker-pressure.pids"
runtime.succeed(textwrap.dedent(f"""
    : > {pressure_pid_file}
    for family in 4 6; do
        for index in $({COREUTILS}/seq 1 40); do
            if test "$family" = 4; then
                destination=TCP4:127.0.0.1:{public_port}
            else
                destination=TCP6:[::1]:{public_port}
            fi
            {SOCAT} "$destination" \
                EXEC:{COREUTILS}/sleep\\ 30 </dev/null >/dev/null 2>&1 &
            printf '%s\n' "$!" >> {pressure_pid_file}
        done
    done
"""))
runtime.succeed(f"{COREUTILS}/sleep 2")
for identity in (
    endpoint_details["ipv4_identity"],
    endpoint_details["ipv6_identity"],
):
    assert broker_process_count(identity["process_group"]) <= 33, identity
runtime.succeed(textwrap.dedent(f"""
    while read -r pid; do
        {COREUTILS}/kill "$pid" 2>/dev/null || true
    done < {pressure_pid_file}
"""))

# Readiness must remain behind a successful observation of the named network
# guarantee. The brokers' independent source filters keep nonloopback clients
# denied while nftables is absent, and the activation fails until restoration.
policy_backup = "/run/postgresql-network-policy.nft"
runtime.succeed(
    f"{NFT} list table inet {shlex.quote(policy['table'])} "
    f"> {policy_backup}"
)
runtime.succeed(
    f"{NFT} delete table inet {shlex.quote(policy['table'])}"
)
runtime.fail(
    f"{COREUTILS}/timeout 3 {SOCAT} - "
    f"TCP4:{ipv4_nonloopback}:{public_port},connect-timeout=2"
)
runtime.succeed(f"{IP} -6 address add fd00::a05/128 dev lo")
runtime.fail(
    f"{COREUTILS}/timeout 3 {SOCAT} - "
    f"'TCP6:[fd00::a05]:{public_port},connect-timeout=2'"
)
runtime.succeed(f"{IP} -6 address del fd00::a05/128 dev lo")

activation_policy_drift = generate_postgresql_activation(
    "/run/postgresql-policy-drift",
    "ability_app",
    "ability_role",
    "sha256:" + "22" * 32,
    "postgresql-upgrade",
    "/run/postgresql-authority-policy-drift",
    postgresql_artifact="upgrade",
)
provision_postgresql_authority(
    activation_policy_drift,
    "/run/postgresql-authority-policy-drift",
)
write_postgresql_host(
    "/run/postgresql-host-policy-drift.nix",
    activation_policy_drift,
)
generation_before_policy_drift = current_generation()
postmaster_before_policy_drift = postmaster_identity(details_readd)
switch_postgresql_host(
    "/run/postgresql-host-policy-drift.nix",
    "policy-drift",
    succeed=False,
)
assert current_generation() == generation_before_policy_drift
assert postmaster_identity(details_readd) == postmaster_before_policy_drift
assert_sql_ready(details_readd, secret_readd)

runtime.succeed(f"{NFT} -f {policy_backup}")
generation_policy_recovered = switch_postgresql_host(
    "/run/postgresql-host-policy-drift.nix",
    "policy-recovered",
)
transaction_policy_recovered, _, bundle_policy_recovered = assert_effect_graph(
    generation_policy_recovered,
    activation_policy_drift,
    noop_operations,
    5,
)
assert_required_edge(
    bundle_policy_recovered,
    activation_policy_drift,
    ("host-network-policy", "observe"),
    ("postgresql", "observe"),
)
assert postmaster_identity(details_readd) == postmaster_before_policy_drift
assert_sql_ready(details_readd, secret_readd)
assert_runtime_redaction(
    generation_policy_recovered,
    transaction_policy_recovered,
    [secret_text_v1, secret_text_v2],
)
