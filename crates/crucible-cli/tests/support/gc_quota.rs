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

#[path = "gc_quota_setup.rs"]
mod setup;
pub use setup::{mark_node, prepare, quota_budget_toml};

/// Retains a genuine inspection scope through decoding a persisted GC journal.
pub struct Inspection {
    marks: std::sync::Arc<dyn crucible_daemon::campaign_store_composition::ImmutableBlobBackend>,
    boundary:
        Box<dyn FnMut() -> Result<(), crucible_daemon::campaign_store_composition::StoreError>>,
    _resources: crucible_cas::owned_decode::ResourceLoan,
}

impl Inspection {
    /// Borrows this inspection's original finite mark and metadata authority.
    ///
    /// # Errors
    /// Refuses expired supervision or unavailable original allocation credits.
    pub fn context(
        &mut self,
    ) -> Result<
        crucible_daemon::CampaignGcOperationContext<'_>,
        crucible_daemon::campaign_store_composition::StoreError,
    > {
        crucible_daemon::CampaignGcOperationContext::new(self.marks.clone(), self.boundary.as_mut())
    }
}

/// Authenticates the selected existing quota for independent stopped-owner inspection.
///
/// # Errors
/// Refuses absent operator policy, mismatched physical quota, or exhausted service credits.
pub fn inspection(store: &Path, scope: &str) -> Result<Inspection, Box<dyn Error>> {
    use crucible_cas::content_store::StorePhysicalQuotaBinder;
    use std::sync::Arc;
    use std::time::Duration;

    let deployment = fs::read_to_string(store)?.parse::<toml::Table>()?;
    let nodes = deployment
        .get("nodes")
        .and_then(toml::Value::as_array)
        .ok_or("inspection nodes missing")?;
    let selected = mark_node(&deployment)?;
    let node = nodes
        .iter()
        .find(|node| node.get("id").and_then(toml::Value::as_str) == Some(selected.as_str()))
        .ok_or("inspection node missing")?;
    let spec = node
        .get("spec")
        .and_then(toml::Value::as_table)
        .ok_or("inspection node spec missing")?;
    if spec.get("kind").and_then(toml::Value::as_str) != Some("physical-quota") {
        return Err("GC inspection requires the real guarded physical node".into());
    }
    let child = spec
        .get("child")
        .and_then(toml::Value::as_str)
        .ok_or("inspection child missing")?;
    let child = nodes
        .iter()
        .find(|node| node.get("id").and_then(toml::Value::as_str) == Some(child))
        .ok_or("inspection leaf missing")?;
    let directory = child
        .get("spec")
        .and_then(|spec| spec.get("root"))
        .and_then(toml::Value::as_str)
        .ok_or("inspection leaf root missing")?;
    let project = u32::try_from(
        spec.get("project_id")
            .and_then(toml::Value::as_integer)
            .ok_or("inspection project missing")?,
    )?;
    let configuration = quota_service_config(
        Duration::from_secs(300),
        crucible_api::host_operational::HostResourceVector {
            resident_peak_bytes: 134217728,
            backing_peak_bytes: 2147483648,
            metadata_bytes: 67108864,
            staging_bytes: 8388608,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 256,
        },
    )?;
    let operation = configuration
        .supervisor
        .begin(crucible_api::host_operational::HostOperationClass::Writeback)?;
    let binder = crucible_daemon::LinuxProjectQuotaBinder::new(configuration)?;
    let quota = binder.bind(Path::new(directory), project, 2147483648, 1048576)?;
    let resources = quota.reserve_resources(0, std::mem::size_of::<Inspection>() as u64 + 512)?;
    let marks = Arc::clone(&quota).gc_mark_backend(scope)?;
    Ok(Inspection {
        marks,
        boundary: Box::new(move || {
            operation.wait_slice().map(|_| ()).map_err(|source| {
                crucible_daemon::campaign_store_composition::StoreError::Supervision {
                    source: Box::new(source),
                }
            })
        }),
        _resources: resources,
    })
}

/// Shares one finite inspection service across the composed physical leaves.
///
/// # Errors
/// Refuses absent operator identity, mismatched installed quotas or exhausted
/// original resource credits before constructing an inspection graph.
pub fn composed_inspection(read_source: &Path) -> Result<ComposedInspection, Box<dyn Error>> {
    use crucible_cas::content_store::{
        StoreGraphPhysicalQuotaBinders, StorePhysicalQuotaBinder, StorePhysicalQuotaPolicyId,
    };
    use crucible_session::engine::owned_decode::DecodeBudget;
    use std::sync::Arc;
    use std::time::Duration;

    let project = std::env::var("CRUCIBLE_FLIGHT_STORE_PROJECT")?.parse::<u32>()?;
    let binder = crucible_daemon::LinuxProjectQuotaBinder::new(quota_service_config(
        Duration::from_secs(300),
        crucible_api::host_operational::HostResourceVector {
            resident_peak_bytes: 134217728,
            backing_peak_bytes: 2147483648,
            metadata_bytes: 67108864,
            staging_bytes: 8388608,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 256,
        },
    )?)?;
    let source = binder.bind(read_source, project, 2147483648, 1048576)?;
    let decoding = DecodeBudget::for_store(Arc::clone(&source))?;
    decoding.charge_bytes(
        (std::mem::size_of::<InspectionBinder>()
            + 2 * std::mem::size_of::<usize>()
            + read_source.as_os_str().len()) as u64,
    )?;
    decoding
        .charge_btree_entry::<StorePhysicalQuotaPolicyId, Arc<dyn StorePhysicalQuotaBinder>>()?;
    let mut binders = StoreGraphPhysicalQuotaBinders::new();
    binders.insert(
        StorePhysicalQuotaPolicyId::new("native/gc-store")?,
        Arc::new(InspectionBinder {
            binder,
            source_path: read_source.to_owned(),
            source,
            project,
        }),
    )?;
    Ok(ComposedInspection {
        binders,
        decoding,
        project,
    })
}

/// Retains one original namespace authority while opening its physical leaves.
pub struct ComposedInspection {
    /// Maps the fixture policy to its shared finite inspection service.
    pub binders: crucible_cas::content_store::StoreGraphPhysicalQuotaBinders,
    /// Keeps decoded inspection metadata charged to that same service.
    pub decoding: crucible_session::engine::owned_decode::DecodeBudget,
    /// Names the exact operator-installed physical project.
    pub project: u32,
}

struct InspectionBinder {
    binder: crucible_daemon::LinuxProjectQuotaBinder,
    source_path: std::path::PathBuf,
    source: std::sync::Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>,
    project: u32,
}

impl crucible_cas::content_store::StorePhysicalQuotaBinder for InspectionBinder {
    fn bind(
        &self,
        root: &Path,
        project_id: u32,
        maximum_physical_bytes: u64,
        maximum_inodes: u64,
    ) -> Result<
        std::sync::Arc<dyn crucible_cas::content_store::StorePhysicalQuotaGuard>,
        crucible_cas::content_store::StoreError,
    > {
        if root == self.source_path {
            if project_id != self.project
                || maximum_physical_bytes != 2147483648
                || maximum_inodes != 1048576
            {
                return Err(crucible_cas::content_store::StoreError::Quota);
            }
            self.source.verify()?;
            return Ok(std::sync::Arc::clone(&self.source));
        }
        crucible_cas::content_store::StorePhysicalQuotaBinder::bind(
            &self.binder,
            root,
            project_id,
            maximum_physical_bytes,
            maximum_inodes,
        )
    }
}

/// Checks a stopped physical leaf under its original installed quota.
///
/// # Errors
/// Refuses unavailable operator quota, malformed leaf limits, or original
/// inspection credit exhaustion before opening a placement.
pub fn contains_stopped_leaf(
    directory: &Path,
    content: crucible_cas::content_store::ContentId,
    compressed_limit: Option<u64>,
) -> Result<bool, Box<dyn Error>> {
    use crucible_cas::content_store::*;
    use std::collections::{BTreeMap, BTreeSet};

    let ComposedInspection {
        binders,
        decoding,
        project: project_id,
    } = composed_inspection(directory)?;
    let _scope = decoding.enter();
    for _ in 0..2 {
        decoding.charge_btree_entry::<StoreNodeId, StoreNodeSpec>()?;
    }
    decoding.charge_bytes(
        (directory.as_os_str().len() * 2 + std::mem::size_of::<StoreGraphConfig>() + 512) as u64,
    )?;
    let physical = StoreNodeId::new("inspection-physical")?;
    let raw = StoreNodeId::new("inspection-leaf")?;
    let leaf = match compressed_limit {
        Some(maximum_logical_object_bytes) => StoreNodeSpec::CompressedDirectory {
            root: directory.to_owned(),
            maximum_logical_object_bytes,
        },
        None => StoreNodeSpec::Directory {
            root: directory.to_owned(),
        },
    };
    let graph = StoreGraph::build_with_all_capabilities(
        StoreGraphConfig {
            gc_mark_root: None,
            root: physical.clone(),
            admitted_kinds: BTreeSet::from([content.kind()]),
            nodes: BTreeMap::from([
                (raw.clone(), leaf),
                (
                    physical,
                    StoreNodeSpec::PhysicalQuota {
                        child: raw,
                        policy: StorePhysicalQuotaPolicyId::new("native/gc-store")?,
                        project_id,
                        maximum_physical_bytes: 2147483648,
                        maximum_inodes: 1048576,
                    },
                ),
            ]),
        },
        &StoreGraphKeyring::new(),
        &StoreGraphNamespaceAuthorizers::new(),
        &StoreGraphObjectProfilers::new(),
        &binders,
        &StoreGraphS3Clients::new(),
    )?;
    Ok(graph.contains(content)?)
}

/// Starts one original supervisor for the fixture's independently authored scope.
///
/// # Errors
/// Refuses invalid finite supervision before opening the operator namespace.
pub fn quota_service_config(
    total_timeout: std::time::Duration,
    resources: crucible_api::host_operational::HostResourceVector,
) -> Result<crucible_daemon::CampaignQuotaServiceConfig, Box<dyn Error>> {
    use crucible_api::host_operational::{HostOperationBudget, HostOperationBudgets};
    crucible_daemon::CampaignQuotaServiceConfig::from_authored_budgets(
        HostOperationBudgets {
            classes: [HostOperationBudget {
                poll_interval: std::time::Duration::from_millis(10),
                progress_timeout: None,
                total_timeout: Some(total_timeout),
            }; 14],
        },
        Some(total_timeout),
        resources,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod mark_guard_tests {
    use super::*;

    #[test]
    fn inspection_refuses_unwrapped_mark_namespace_before_binding() -> Result<(), Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let store = temporary.path().join("store.toml");
        fs::write(
            &store,
            r#"
root = "profile"
gc_mark_root = "gc-marks"
[[nodes]]
id = "gc-marks"
[nodes.spec]
kind = "directory"
root = "/declared/marks"
"#,
        )?;

        let failure = match inspection(&store, "unguarded-marks") {
            Ok(_) => return Err("unguarded mark namespace unexpectedly admitted".into()),
            Err(failure) => failure,
        };
        assert_eq!(
            failure.to_string(),
            "GC inspection requires the real guarded physical node"
        );
        Ok(())
    }
}
