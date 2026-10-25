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
    assert!(resources.surface_index.is_none());
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

const SURFACE_INDEX: &str = r#"
[host_tier.domains.public.cache.surface_index]
max_entries = 64
max_node_bytes = 131072
max_index_bytes = 65536
capacity_bytes = 1048576
future_hold_bytes = 327680
"#;

#[test]
fn native_surface_index_preserves_explicit_independent_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse(&format!("{CONFIG}{SURFACE_INDEX}"))?;
    let index = config
        .host_tier()
        .and_then(|host| host.domains["public"].cache.as_ref())
        .and_then(|cache| cache.surface_index)
        .ok_or("missing explicit surface-index policy")?;

    assert_eq!(index.max_entries, 64);
    assert_eq!(index.max_node_bytes, 131072);
    assert_eq!(index.max_index_bytes, 65536);
    assert_eq!(index.capacity_bytes, 1048576);
    assert_eq!(index.future_hold_bytes, 327680);
    Ok(())
}

#[test]
fn native_surface_index_refuses_incomplete_unfunded_and_overflowing_bounds() {
    for field in [
        "max_entries = 64\n",
        "max_node_bytes = 131072\n",
        "max_index_bytes = 65536\n",
        "capacity_bytes = 1048576\n",
        "future_hold_bytes = 327680\n",
    ] {
        let incomplete = SURFACE_INDEX.replace(field, "");
        assert!(
            Config::parse(&format!("{CONFIG}{incomplete}")).is_err(),
            "{field}"
        );
    }

    for (field, invalid) in [
        ("max_entries = 64", "max_entries = 0"),
        ("max_entries = 64", "max_entries = 4294967296"),
        ("max_node_bytes = 131072", "max_node_bytes = 31"),
        ("max_index_bytes = 65536", "max_index_bytes = 0"),
        ("capacity_bytes = 1048576", "capacity_bytes = 65535"),
        ("capacity_bytes = 1048576", "capacity_bytes = 25165825"),
        ("future_hold_bytes = 327680", "future_hold_bytes = 327679"),
        ("future_hold_bytes = 327680", "future_hold_bytes = 25165825"),
        (
            "max_index_bytes = 65536",
            "max_index_bytes = 18446744073709551615",
        ),
        ("max_entries", "unknown_entries"),
    ] {
        let refused = SURFACE_INDEX.replace(field, invalid);
        assert!(
            Config::parse(&format!("{CONFIG}{refused}")).is_err(),
            "{invalid}"
        );
    }
}

const MAINTENANCE: &str = r#"
[host_tier.publisher]
socket_path = "/run/terrane-publish/publisher.sock"
serve_uid = 840
publish_uid = 841
content_uid = 840
content_gid = 842
max_connections = 8
[host_tier.maintenance]
gc_uid = 843
max_connections = 8
max_requests = 1
connection_timeout_ms = 30000
request_timeout_ms = 20000
[host_tier.maintenance.sockets]
public = "/run/terrane-maintenance/public.sock"
"#;

#[test]
fn maintenance_preserves_explicit_bounds_and_requires_complete_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(Config::parse(&format!("{CONFIG}{MAINTENANCE}")).is_err());
    let text = format!("{CONFIG}{SURFACE_INDEX}{MAINTENANCE}");
    let config = Config::parse(&text)?;
    let settings = config
        .host_tier()
        .and_then(|host| host.maintenance.as_ref())
        .ok_or("missing explicit maintenance settings")?;

    assert_eq!(settings.gc_uid, 843);
    assert_eq!(settings.request_timeout_ms, 20000);
    assert_eq!(
        settings.sockets["public"],
        "/run/terrane-maintenance/public.sock"
    );
    for field in [
        "gc_uid = 843\n",
        "max_connections = 8\n",
        "max_requests = 1\n",
        "connection_timeout_ms = 30000\n",
        "request_timeout_ms = 20000\n",
        "public = \"/run/terrane-maintenance/public.sock\"\n",
    ] {
        assert!(Config::parse(&text.replace(field, "")).is_err(), "{field}");
    }
    Ok(())
}

#[test]
fn maintenance_refuses_colliding_roles_unbounded_transport_and_unknown_fields() {
    let text = format!("{CONFIG}{SURFACE_INDEX}{MAINTENANCE}");
    for (field, replacement) in [
        ("gc_uid = 843", "gc_uid = 840"),
        ("gc_uid = 843", "gc_uid = 841"),
        ("gc_uid = 843", "gc_uid = 4294967295"),
        ("max_connections = 8", "max_connections = 0"),
        ("max_connections = 8", "max_connections = 1025"),
        ("max_requests = 1", "max_requests = 0"),
        ("max_requests = 1", "max_requests = 4097"),
        (
            "connection_timeout_ms = 30000",
            "connection_timeout_ms = 300001",
        ),
        ("request_timeout_ms = 20000", "request_timeout_ms = 0"),
        ("request_timeout_ms = 20000", "request_timeout_ms = 30001"),
        ("gc_uid", "unknown_gc_uid"),
    ] {
        assert!(
            Config::parse(&text.replace(field, replacement)).is_err(),
            "{replacement}"
        );
    }
}

#[test]
fn maintenance_refuses_ambiguous_endpoints_and_incomplete_native_inventory()
-> Result<(), Box<dyn std::error::Error>> {
    let text = format!("{CONFIG}{SURFACE_INDEX}{MAINTENANCE}");
    for path in [
        "/",
        "relative.sock",
        "/run//maintenance.sock",
        "/run/./maintenance.sock",
        "/run/../maintenance.sock",
        "/var/lib/terrane/public/maintenance.sock",
        "/var/lib",
        "/run/terrane-publish/publisher.sock",
        "/run/terrane-publish/publisher.sock/child",
    ] {
        assert!(
            Config::parse(&text.replace("/run/terrane-maintenance/public.sock", path)).is_err(),
            "{path}"
        );
    }
    let long_path = format!("/run/{}", "x".repeat(108));
    assert!(
        Config::parse(&text.replace("/run/terrane-maintenance/public.sock", &long_path)).is_err()
    );
    assert!(
        Config::parse(&text.replace(
            "public = \"/run/terrane-maintenance/public.sock\"",
            "unknown = \"/run/terrane-maintenance/public.sock\""
        ))
        .is_err()
    );

    let mut host = Config::parse(&text)?
        .host_tier()
        .ok_or("missing host")?
        .clone();
    let settings = host.maintenance.clone().ok_or("missing maintenance")?;
    host.publisher = None;
    assert!(settings.validate(&host).is_err());
    host = Config::parse(&text)?
        .host_tier()
        .ok_or("missing host")?
        .clone();
    host.domains
        .get_mut("public")
        .ok_or("missing domain")?
        .cache = None;
    assert!(settings.validate(&host).is_err());

    host = Config::parse(&text)?
        .host_tier()
        .ok_or("missing host")?
        .clone();
    let mut settings = settings;
    let private = host.domains["public"].clone();
    host.domains.insert("private:operator".into(), private);
    assert!(settings.validate(&host).is_err());
    for duplicate in [
        "/run/terrane-maintenance/public.sock",
        "/run/terrane-maintenance/public.sock/child",
    ] {
        settings
            .sockets
            .insert("private:operator".into(), duplicate.into());
        assert!(settings.validate(&host).is_err());
    }
    Ok(())
}
