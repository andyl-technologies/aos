//! Operator-installed quota projection for real CLI maintenance flights.
//!
//! The disposable kernel harness installs one ext4 project before these
//! fixtures allocate files. Ordinary component fixtures retain their raw store
//! and cannot claim admitted maintenance authority. The generated store uses:
//!
//! ```toml
//! physical_quota_policies = ["native/gc-store"]
//! [physical_quota_service]
//! lifetime_ms = 2700000
//! ```

use std::error::Error;
use std::fs;
use std::path::Path;

/// Wraps the fixture's physical leaves under its actual installed project.
///
/// # Errors
/// Refuses malformed fixture configuration or missing operator project identity.
pub fn prepare(store: &Path) -> Result<Option<String>, Box<dyn Error>> {
    let Some(project) = std::env::var_os("CRUCIBLE_FLIGHT_STORE_PROJECT") else {
        return Ok(None);
    };
    let project = project
        .to_str()
        .ok_or("quota project is not UTF-8")?
        .parse::<u32>()?;
    let mut deployment = fs::read_to_string(store)?.parse::<toml::Table>()?;
    if deployment.contains_key("physical_quota_service") {
        return Ok(deployment
            .get("root")
            .and_then(toml::Value::as_str)
            .map(str::to_owned));
    }
    let root = deployment
        .get("root")
        .and_then(toml::Value::as_str)
        .ok_or("fixture root is missing")?
        .to_owned();
    let nodes = deployment
        .get_mut("nodes")
        .and_then(toml::Value::as_array_mut)
        .ok_or("fixture nodes are missing")?;
    let mark_node = if nodes
        .iter()
        .any(|node| node.get("id").and_then(toml::Value::as_str) == Some("read-source"))
    {
        String::from("read-source")
    } else {
        root
    };
    let mut guarded = Vec::new();
    for node in nodes.iter_mut() {
        let table = node.as_table_mut().ok_or("fixture node is not a table")?;
        let spec = table
            .get("spec")
            .and_then(toml::Value::as_table)
            .ok_or("fixture node spec is missing")?;
        let kind = spec
            .get("kind")
            .and_then(toml::Value::as_str)
            .ok_or("fixture kind is missing")?;
        if !matches!(
            kind,
            "directory" | "compressed-directory" | "packed" | "sqlite"
        ) {
            continue;
        }
        let id = table
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or("fixture node ID is missing")?
            .to_owned();
        let raw_id = format!("raw-{id}");
        table.insert(String::from("id"), toml::Value::String(raw_id.clone()));
        let wrapper = format!(
            r#"
id = {id:?}
[spec]
kind = "physical-quota"
child = {raw_id:?}
policy = "native/gc-store"
project_id = {project}
maximum_physical_bytes = 2147483648
maximum_inodes = 1048576
"#
        )
        .parse::<toml::Table>()?;
        guarded.push(toml::Value::Table(wrapper));
    }
    nodes.extend(guarded);
    deployment.insert(
        String::from("physical_quota_policies"),
        toml::Value::Array(vec![toml::Value::String(String::from("native/gc-store"))]),
    );
    // The four-leaf composed flight retains four bindings concurrently. This
    // independent finite descriptor policy covers them and their real readers.
    let service = format!(
        r#"
lifetime_ms = 2700000
[resources]
resident_peak_bytes = 134217728
backing_peak_bytes = 2147483648
metadata_bytes = 67108864
staging_bytes = 8388608
paging_io_slots = 1
cpu_slots = 1
task_slots = 1
file_descriptors = 256
{roster}
"#,
        roster = quota_budget_toml("host_operation_budgets", 2700000)
    )
    .parse::<toml::Table>()?;
    deployment.insert(
        String::from("physical_quota_service"),
        toml::Value::Table(service),
    );
    fs::write(store, toml::to_string(&deployment)?)?;
    Ok(Some(mark_node))
}
/// Authors the complete finite roster used by disposable maintenance fixtures.
pub fn quota_budget_toml(prefix: &str, total_timeout_ms: u64) -> String {
    QUOTA_CLASS_NAMES.iter().map(|name| {
        format!("\n[{prefix}.{name}]\npoll_interval_ms = 10\ntotal_timeout_ms = {total_timeout_ms}\n")
    }).collect()
}

const QUOTA_CLASS_NAMES: [&str; 14] = [
    "setup",
    "quantum",
    "page_in",
    "writeback",
    "fingerprint_initialization",
    "fingerprint_update",
    "quiescence",
    "checkpoint_capture",
    "checkpoint_publication",
    "restore",
    "fork_rearm",
    "transfer",
    "preparation",
    "cleanup",
];
