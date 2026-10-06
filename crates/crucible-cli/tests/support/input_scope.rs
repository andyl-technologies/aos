//! Retained input authority for disposable-kernel process fixtures.
//!
//! The harness independently installs the source project before this helper
//! authenticates its exact policy. The target CLI process uses a different
//! installed namespace. Both retain their own original service and deadlines.
//!
//! ```toml
//! root = "/storage/source"
//! project_id = 60000
//! maximum_bytes = 2147483648
//! maximum_inodes = 1048576
//! [resources]
//! resident_peak_bytes = 134217728
//! backing_peak_bytes = 2147483648
//! metadata_bytes = 67108864
//! staging_bytes = 8388608
//! paging_io_slots = 1
//! cpu_slots = 1
//! task_slots = 1
//! file_descriptors = 256
//! [host_operation_budgets.setup]
//! poll_interval_ms = 10
//! total_timeout_ms = 2700000
//! ```
//!
//! All fourteen classes are required; there is no component or absent-policy
//! fallback. A synchronous fixture enters the returned original decode budget.
//! An asynchronous fixture passes that budget to its per-poll adapter instead.

// crucible-lint: allow clippy-disallowed-method -- native fixtures authenticate the operator policy and physical filesystem before process work.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::error::Error;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crucible_api::host_operational::{
    HostOperationBudget, HostOperationBudgets, HostResourceVector,
};
use crucible_daemon::campaign_store_composition::{
    StorePhysicalQuotaBinder, StorePhysicalQuotaGuard,
};
use crucible_session::engine::owned_decode::DecodeBudget;
use serde::Deserialize;

/// Retains the authenticated source namespace through fixture borrowers.
pub struct NativeInputResources {
    /// Exact installed source quota retained through all fixture byte borrowers.
    pub authority: Arc<dyn StorePhysicalQuotaGuard>,
    /// Original resource budget used by synchronous or per-poll decoders.
    pub decoding: DecodeBudget,
}

/// Authenticates the operator's exact source project and original finite roster.
///
/// # Errors
/// Refuses absent or malformed policy, unexpected class names, unbounded
/// infrastructure, mismatched installed quota, or exhausted service resources.
pub fn open() -> Result<NativeInputResources, Box<dyn Error>> {
    let path = std::env::var_os("CRUCIBLE_FLIGHT_SOURCE_POLICY")
        .ok_or("native input fixture requires CRUCIBLE_FLIGHT_SOURCE_POLICY")?;
    let mut policy_bytes = [0_u8; 65536];
    let mut file = std::fs::File::open(path)?;
    let length = usize::try_from(file.metadata()?.len())?;
    if length > policy_bytes.len() {
        return Err("native source policy exceeds its bounded configuration extent".into());
    }
    file.read_exact(&mut policy_bytes[..length])?;
    let policy: SourcePolicy = toml::from_str(std::str::from_utf8(&policy_bytes[..length])?)?;
    drop(file);

    if policy.host_operation_budgets.len() != CLASS_NAMES.len() {
        return Err("native source policy requires exactly fourteen operation classes".into());
    }
    let mut classes = [HostOperationBudget {
        poll_interval: Duration::ZERO,
        progress_timeout: None,
        total_timeout: None,
    }; 14];
    for (index, name) in CLASS_NAMES.into_iter().enumerate() {
        let authored = policy
            .host_operation_budgets
            .get(name)
            .ok_or("native source policy is missing an operation class")?;
        classes[index] = HostOperationBudget {
            poll_interval: Duration::from_millis(authored.poll_interval_ms),
            progress_timeout: authored.progress_timeout_ms.map(Duration::from_millis),
            total_timeout: authored.total_timeout_ms.map(Duration::from_millis),
        };
    }
    let service = crucible_daemon::CampaignQuotaServiceConfig::from_authored_budgets(
        HostOperationBudgets { classes },
        None,
        policy.resources.vector(),
    )?;
    let binder = crucible_daemon::LinuxProjectQuotaBinder::new(service)?;
    let authority = binder.bind(
        &policy.root,
        policy.project_id,
        policy.maximum_bytes,
        policy.maximum_inodes,
    )?;
    let decoding = DecodeBudget::for_store(Arc::clone(&authority))?;
    Ok(NativeInputResources {
        authority,
        decoding,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePolicy {
    root: PathBuf,
    project_id: u32,
    maximum_bytes: u64,
    maximum_inodes: u64,
    resources: Resources,
    host_operation_budgets: BTreeMap<String, Budget>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Resources {
    resident_peak_bytes: u64,
    backing_peak_bytes: u64,
    metadata_bytes: u64,
    staging_bytes: u64,
    paging_io_slots: u64,
    cpu_slots: u64,
    task_slots: u64,
    file_descriptors: u64,
}

impl Resources {
    fn vector(&self) -> HostResourceVector {
        HostResourceVector {
            resident_peak_bytes: self.resident_peak_bytes,
            backing_peak_bytes: self.backing_peak_bytes,
            metadata_bytes: self.metadata_bytes,
            staging_bytes: self.staging_bytes,
            paging_io_slots: self.paging_io_slots,
            cpu_slots: self.cpu_slots,
            task_slots: self.task_slots,
            file_descriptors: self.file_descriptors,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    poll_interval_ms: u64,
    progress_timeout_ms: Option<u64>,
    total_timeout_ms: Option<u64>,
}

const CLASS_NAMES: [&str; 14] = [
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
