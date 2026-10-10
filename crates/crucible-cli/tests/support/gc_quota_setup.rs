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
        return Ok(Some(mark_node(&deployment)?));
    }
    let mark_node = mark_node(&deployment)?;
    let nodes = deployment
        .get_mut("nodes")
        .and_then(toml::Value::as_array_mut)
        .ok_or("fixture nodes are missing")?;
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

/// Selects the fixture's explicitly declared mark leaf without redirecting data.
///
/// # Errors
/// Refuses a missing graph root or a remote/composite node named as local marks.
pub fn mark_node(deployment: &toml::Table) -> Result<String, Box<dyn Error>> {
    let root = deployment
        .get("root")
        .and_then(toml::Value::as_str)
        .ok_or("fixture root is missing")?;
    let nodes = deployment
        .get("nodes")
        .and_then(toml::Value::as_array)
        .ok_or("fixture nodes are missing")?;
    if let Some(declared) = deployment.get("gc_mark_root") {
        let declared = declared
            .as_str()
            .ok_or("fixture GC mark root must be a node ID string")?;
        let marks = nodes
            .iter()
            .find(|node| node.get("id").and_then(toml::Value::as_str) == Some(declared))
            .ok_or("fixture declared GC mark root is missing")?;
        let kind = marks
            .get("spec")
            .and_then(|spec| spec.get("kind"))
            .and_then(toml::Value::as_str)
            .ok_or("fixture mark namespace kind is missing")?;
        // Before operator projection this is the authored Directory. Projection
        // keeps this declared ID on its genuine physical-quota wrapper.
        if !matches!(kind, "directory" | "physical-quota") {
            return Err("fixture marks require an explicitly declared local namespace".into());
        }
        return Ok(declared.to_owned());
    }
    if let Some(source) = nodes
        .iter()
        .find(|node| node.get("id").and_then(toml::Value::as_str) == Some("read-source"))
    {
        let remote = source
            .get("spec")
            .and_then(|spec| spec.get("kind"))
            .and_then(toml::Value::as_str)
            == Some("s3");
        if remote
            && nodes
                .iter()
                .any(|node| node.get("id").and_then(toml::Value::as_str) == Some("read-cache"))
        {
            // Composed S3 already owns this guarded local leaf. Marks borrow
            // its namespace without adding a cache or changing any data route.
            return Ok(String::from("read-cache"));
        }
        Ok(String::from("read-source"))
    } else {
        Ok(root.to_owned())
    }
}

#[cfg(test)]
mod mark_namespace_tests {
    use super::*;

    #[test]
    fn remote_named_mark_namespace_is_refused() -> Result<(), Box<dyn Error>> {
        let deployment = r#"
root = "profile"
gc_mark_root = "gc-marks"
[[nodes]]
id = "gc-marks"
[nodes.spec]
kind = "s3"
"#
        .parse::<toml::Table>()?;
        assert!(mark_node(&deployment).is_err());
        Ok(())
    }

    #[test]
    fn explicit_mark_selection_does_not_mutate_the_remote_data_root() -> Result<(), Box<dyn Error>>
    {
        let deployment = r#"
root = "profile"
gc_mark_root = "gc-marks"
[[nodes]]
id = "gc-marks"
[nodes.spec]
kind = "directory"
root = "/declared/marks"
[[nodes]]
id = "profile"
[nodes.spec]
kind = "s3"
"#
        .parse::<toml::Table>()?;
        assert_eq!(mark_node(&deployment)?, "gc-marks");
        assert_eq!(deployment["root"].as_str(), Some("profile"));
        Ok(())
    }

    #[test]
    fn declared_mark_root_does_not_fall_back_to_another_local_node() -> Result<(), Box<dyn Error>> {
        let mut deployment = r#"
root = "profile"
gc_mark_root = "missing-marks"
[[nodes]]
id = "gc-marks"
[nodes.spec]
kind = "directory"
root = "/declared/marks"
"#
        .parse::<toml::Table>()?;
        assert!(mark_node(&deployment).is_err());

        deployment.insert(String::from("gc_mark_root"), toml::Value::Integer(1));
        assert!(mark_node(&deployment).is_err());
        Ok(())
    }

    #[test]
    fn declared_guarded_root_keeps_its_identity_after_projection() -> Result<(), Box<dyn Error>> {
        let deployment = r#"
root = "profile"
gc_mark_root = "maintenance"
[[nodes]]
id = "maintenance"
[nodes.spec]
kind = "physical-quota"
child = "raw-maintenance"
[[nodes]]
id = "raw-maintenance"
[nodes.spec]
kind = "directory"
root = "/declared/marks"
"#
        .parse::<toml::Table>()?;
        assert_eq!(mark_node(&deployment)?, "maintenance");
        assert_eq!(deployment["root"].as_str(), Some("profile"));
        Ok(())
    }

    #[test]
    fn composed_remote_graph_selects_its_existing_local_cache() -> Result<(), Box<dyn Error>> {
        let deployment = r#"
root = "verified"
[[nodes]]
id = "read-source"
[nodes.spec]
kind = "s3"
[[nodes]]
id = "read-cache"
[nodes.spec]
kind = "packed"
root = "/declared/cache"
"#
        .parse::<toml::Table>()?;
        assert_eq!(mark_node(&deployment)?, "read-cache");
        assert_eq!(deployment["root"].as_str(), Some("verified"));
        Ok(())
    }
}
