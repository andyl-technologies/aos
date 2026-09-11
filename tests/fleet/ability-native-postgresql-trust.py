# A terminal trust request must fail preflight before allocating host resources.


def runtime_tree_snapshot():
    return runtime.succeed(textwrap.dedent(f"""
        set -eu
        {FIND} {shlex.quote(RUNTIME_ROOT)} -type f -print \
          | {COREUTILS}/sort \
          | while IFS= read -r path; do
              {COREUTILS}/sha256sum "$path"
            done
    """))


trust_tree_before = runtime_tree_snapshot()
trust_generation_before = current_generation()
trust_pid_before = postmaster_identity(details_hold)
activation_trust = generate_postgresql_trust_activation(
    "/run/postgresql-trust",
    "trust_database",
    "trust_role",
    "postgresql-trust",
    "/run/postgresql-authority-trust",
)
provision_postgresql_authority(
    activation_trust,
    "/run/postgresql-authority-trust",
)
trust_entries = native_resource_map(activation_trust)["entries"]
assert {
    entry["qualification"]["kind"]
    for entry in trust_entries
} == {
    "host-network-policy",
    "host-storage",
    "network-endpoint",
    "postgresql",
}, trust_entries
trust_paths = [state_path(entry) for entry in trust_entries]
for path in trust_paths:
    runtime.fail(f"test -e {shlex.quote(path)}")

write_postgresql_host(
    "/run/postgresql-host-trust.nix",
    activation_trust,
)
trust_failure = switch_postgresql_host(
    "/run/postgresql-host-trust.nix",
    "trust",
    succeed=False,
)
assert (
    "PostgreSQL native execution requires authenticated credential delivery; "
    "trust authentication is unsupported"
) in trust_failure, trust_failure
assert current_generation() == trust_generation_before
assert postmaster_identity(details_hold) == trust_pid_before
assert runtime_tree_snapshot() == trust_tree_before
for path in trust_paths:
    runtime.fail(f"test -e {shlex.quote(path)}")
runtime.fail(
    f"{COREUTILS}/timeout 2 {PG_ISREADY} -h 127.0.0.1 "
    "-p 20063 -t 1"
)
assert_sql_ready(details_hold, secret_hold)
