# Fixed principal-pool exhaustion and retained-slot reuse flight.


def capacity_cluster(index):
    return (
        f"capacity_db_{index:02d}",
        f"capacity_role_{index:02d}",
        "sha256:" + f"{index:064x}",
        f"postgresql-capacity-{index:02d}",
    )


def persistent_state_snapshot():
    return {
        kind: {
            json.dumps(state["resource"], sort_keys=True): state
            for state in all_runtime_states(kind)
        }
        for kind in ("host-storage", "postgresql")
    }


capacity_retained = [
    (
        "ability_app",
        "ability_role",
        "sha256:" + "33" * 32,
        "postgresql-capacity-retained-ability",
    ),
    (
        "isolation_database",
        "isolation_role",
        "sha256:" + "44" * 32,
        "postgresql-capacity-retained-isolation",
    ),
    (
        "recovery_database",
        "recovery_role",
        "sha256:" + "56" * 32,
        "postgresql-capacity-retained-recovery",
    ),
    (
        "fault_before_database",
        "fault_before_role",
        "sha256:" + "61" * 32,
        "postgresql-capacity-retained-fault-before",
    ),
]
capacity_additional = capacity_retained + [
    capacity_cluster(index)
    for index in range(1, 60)
]
assert len(capacity_additional) == 63
activation_capacity = generate_postgresql_activation(
    "/run/postgresql-capacity",
    "fault_after_database",
    "fault_after_role",
    "sha256:" + "68" * 32,
    "postgresql-capacity-retained-fault-after",
    "/run/postgresql-authority-capacity",
    postgresql_artifact="upgrade",
    additional=capacity_additional,
)
provision_postgresql_authority(
    activation_capacity,
    "/run/postgresql-authority-capacity",
)
capacity_entries = native_resource_map(activation_capacity)["entries"]
capacity_counts = {}
for entry in capacity_entries:
    kind = entry["qualification"]["kind"]
    capacity_counts[kind] = capacity_counts.get(kind, 0) + 1
assert capacity_counts == {
    "credential-delivery": 64,
    "host-network-policy": 64,
    "host-storage": 64,
    "network-endpoint": 64,
    "postgresql": 64,
}, capacity_counts

write_postgresql_host(
    "/run/postgresql-host-capacity.nix",
    activation_capacity,
)
generation_capacity = switch_postgresql_host(
    "/run/postgresql-host-capacity.nix",
    "capacity",
)
capacity_active = persistent_state_snapshot()
assert len(capacity_active["host-storage"]) == 64, capacity_active
assert len(capacity_active["postgresql"]) == 64, capacity_active
assert {
    state["details"]["binding"]["slot"]
    for state in capacity_active["host-storage"].values()
} == set(range(64)), capacity_active["host-storage"]
assert {
    state["details"]["slot"]
    for state in capacity_active["postgresql"].values()
} == set(range(64)), capacity_active["postgresql"]
for state in capacity_active["postgresql"].values():
    assert state["details"]["phase"] == "active", state
    assert_process_boundary(state["details"])

# The removal request names the exact same aggregate members. Persistent
# storage leases and stopped PostgreSQL identities remain after teardown.
activation_capacity_remove = generate_postgresql_activation(
    "/run/postgresql-capacity-remove",
    "fault_after_database",
    "fault_after_role",
    "sha256:" + "68" * 32,
    "postgresql-capacity-retained-fault-after",
    "/run/postgresql-authority-capacity-remove",
    lifecycle="remove",
    postgresql_artifact="upgrade",
    additional=capacity_additional,
)
provision_postgresql_authority(
    activation_capacity_remove,
    "/run/postgresql-authority-capacity-remove",
)
assert native_resource_map(activation_capacity_remove)["entries"] == []
write_postgresql_host(
    "/run/postgresql-host-capacity-remove.nix",
    activation_capacity_remove,
)
generation_capacity_remove = switch_postgresql_host(
    "/run/postgresql-host-capacity-remove.nix",
    "capacity-remove",
)

capacity_released = persistent_state_snapshot()
assert set(capacity_released["host-storage"]) == set(
    capacity_active["host-storage"]
), capacity_released
assert set(capacity_released["postgresql"]) == set(
    capacity_active["postgresql"]
), capacity_released
assert {
    state["details"]["binding"]["slot"]
    for state in capacity_released["host-storage"].values()
} == set(range(64)), capacity_released["host-storage"]
assert {
    state["details"]["slot"]
    for state in capacity_released["postgresql"].values()
} == set(range(64)), capacity_released["postgresql"]
for state in capacity_released["host-storage"].values():
    assert state["details"]["phase"] == "released", state
for state in capacity_released["postgresql"].values():
    assert state["details"]["phase"] == "stopped", state

activation_overflow = generate_postgresql_activation(
    "/run/postgresql-capacity-overflow",
    "capacity_overflow",
    "capacity_overflow_role",
    "sha256:" + "65" * 32,
    "postgresql-capacity-overflow",
    "/run/postgresql-authority-capacity-overflow",
    postgresql_artifact="upgrade",
)
provision_postgresql_authority(
    activation_overflow,
    "/run/postgresql-authority-capacity-overflow",
)
overflow_entries = resource_entries(activation_overflow)
overflow_paths = [
    state_path(entry)
    for entry in overflow_entries.values()
]
for path in overflow_paths:
    runtime.fail(f"test -e {shlex.quote(path)}")

write_postgresql_host(
    "/run/postgresql-host-capacity-overflow.nix",
    activation_overflow,
)
generation_before_overflow = current_generation()
overflow_failure = switch_postgresql_host(
    "/run/postgresql-host-capacity-overflow.nix",
    "capacity-overflow",
    succeed=False,
)
assert "PostgreSQL principal-slot pool is exhausted" in overflow_failure, (
    overflow_failure
)
assert current_generation() == generation_before_overflow
assert persistent_state_snapshot() == capacity_released
for path in overflow_paths:
    runtime.fail(f"test -e {shlex.quote(path)}")

# A retained identity can reclaim its pinned slot even while every slot is
# reserved. This is the only admissible allocation after saturation.
released_ability = next(
    state
    for state in capacity_released["postgresql"].values()
    if state["details"]["database"] == "ability_app"
)
released_ability_details = released_ability["details"]
activation_capacity_reuse = generate_postgresql_activation(
    "/run/postgresql-capacity-reuse",
    "ability_app",
    "ability_role",
    "sha256:" + "69" * 32,
    "postgresql-capacity-reuse",
    "/run/postgresql-authority-capacity-reuse",
    postgresql_artifact="upgrade",
)
provision_postgresql_authority(
    activation_capacity_reuse,
    "/run/postgresql-authority-capacity-reuse",
)
write_postgresql_host(
    "/run/postgresql-host-capacity-reuse.nix",
    activation_capacity_reuse,
)
generation_capacity_reuse = switch_postgresql_host(
    "/run/postgresql-host-capacity-reuse.nix",
    "capacity-reuse",
)
capacity_reused = persistent_state_snapshot()
assert set(capacity_reused["host-storage"]) == set(
    capacity_released["host-storage"]
), capacity_reused
assert set(capacity_reused["postgresql"]) == set(
    capacity_released["postgresql"]
), capacity_reused
reused_states = resource_states(activation_capacity_reuse)
reused_details = assert_cluster_layout(reused_states)
assert reused_details["slot"] == released_ability_details["slot"]
assert reused_details["data_path"] == released_ability_details["data_path"]
assert reused_details["data_system_identifier"] == (
    released_ability_details["data_system_identifier"]
)
assert_candidate_publication(reused_details)
assert_process_boundary(reused_details)
assert_sql_ready(
    reused_details,
    "/run/postgresql-capacity-reuse/test-only/credential.secret",
)
