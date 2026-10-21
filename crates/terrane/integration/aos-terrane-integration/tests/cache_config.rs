//! Checks explicit native cache resource syntax without opening host services.

use terrane_sdk::config::Config;

const CONFIG: &str = r#"
role = "serve"
store = "disk(/var/lib/terrane)"
[host_tier]
path = "/var/lib/terrane"
size_bytes = 50331648
reassembly = "never"
[host_tier.domains.public]
path = "/var/lib/terrane/public"
wipe = "none"
[host_tier.domains.public.cache]
state_gid = 844
capacity_bytes = 25165824
low_watermark_bytes = 16777216
probation_bytes = 65536
release_grace_seconds = 30
scan_limit = 64
max_read_bytes = 2097152
state_bytes = 65536
state_records = 64
inventory_entries = 128
queued_commands = 4
metadata_sync_hold_bytes = 262144
publisher_wait_budget_ms = 10000
consumer_lease_seconds = 30
[host_tier.domains.public.cache.portable]
max_file_bytes = 67108864
max_input_bytes = 268435456
max_files = 4096
max_selected_bytes = 33554432
"#;

#[test]
fn explicit_native_cache_resources_preserve_operator_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse(CONFIG)?;
    let resources = config
        .host_tier()
        .and_then(|host| host.domains["public"].cache.as_ref())
        .ok_or("missing explicit cache resources")?;

    assert_eq!(resources.state_records, 64);
    assert_eq!(resources.capacity_bytes, 24 * 1024 * 1024);
    assert_eq!(resources.consumer_lease_seconds, 30);
    assert_eq!(resources.portable.max_files, 4096);
    assert!(resources.index_repair.is_none());
    Ok(())
}

#[test]
fn incomplete_native_cache_resources_never_select_defaults() {
    for field in [
        "state_records = 64\n",
        "consumer_lease_seconds = 30\n",
        "metadata_sync_hold_bytes = 262144\n",
        "max_file_bytes = 67108864\n",
    ] {
        assert!(
            Config::parse(&CONFIG.replace(field, "")).is_err(),
            "{field}"
        );
    }
    assert!(Config::parse(&CONFIG.replace("state_records", "unknown_state_records")).is_err());
}

#[test]
fn native_cache_resources_reject_inconsistent_or_unbounded_policy() {
    for (field, invalid) in [
        ("capacity_bytes = 25165824", "capacity_bytes = 0"),
        (
            "low_watermark_bytes = 16777216",
            "low_watermark_bytes = 99999999",
        ),
        ("state_records = 64", "state_records = 0"),
        ("queued_commands = 4", "queued_commands = 1025"),
        (
            "consumer_lease_seconds = 30",
            "consumer_lease_seconds = 301",
        ),
        (
            "metadata_sync_hold_bytes = 262144",
            "metadata_sync_hold_bytes = 1",
        ),
        ("max_input_bytes = 268435456", "max_input_bytes = 1"),
    ] {
        assert!(
            Config::parse(&CONFIG.replace(field, invalid)).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn native_index_repair_requires_explicit_funded_overlap() {
    let repair = "\n[host_tier.domains.public.cache.index_repair]\nmax_index_bytes = 65536\nfuture_hold_bytes = 327680\n";
    assert!(Config::parse(&format!("{CONFIG}{repair}")).is_ok());
    let unfunded = repair.replace("future_hold_bytes = 327680", "future_hold_bytes = 262144");
    assert!(Config::parse(&format!("{CONFIG}{unfunded}")).is_err());
}
