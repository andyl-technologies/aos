//! Generation-bound maintenance porcelain for configured packed-store leaves.
//!
//! Planning persists the packed backend's canonical v1 plan bytes without
//! changing its index. Apply strictly decodes those bounded bytes and delegates
//! to the separately retained graph-administration capability, whose backend
//! checks configuration, incarnation, generation, index digest, and accounting
//! before publishing replacement packs.
//!
//! The durable plan file contains exactly one canonical backend plan:
//!
//! ```text
//! PackedRepackPlanV1 = PackedRepackPlan::canonical_bytes()
//! ```
//!
//! [`PackedRepackPlan`] owns that registered v1 encoding and its strict,
//! checksummed decoder.

use super::*;

use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

use crucible_daemon::campaign_store_composition::{
    PackedRepackPlan, PackedRepackPlanId, PackedStorageAccounting, StoreGraphConfigurationId,
    StoreGraphPackedRepackAdmin, StoreNodeId,
};
use rustix::fs::{Mode, OFlags, open};
use serde::Serialize;

use crate::cli_campaign_store::load_campaign_store_maintenance_observational;

const STORE_REPACK_REPORT_SCHEMA: &str = "crucible.cli.store-repack.v1";
const MAXIMUM_REPACK_PLAN_BYTES: usize = 1_024;
const MAXIMUM_REPACK_PATH_BYTES: usize = 4_095;

#[derive(Clone, Copy)]
enum PlanDisposition {
    Created,
    Existing,
}

#[derive(Serialize)]
struct StoreRepackReport {
    schema: &'static str,
    operation: &'static str,
    configuration: String,
    node: String,
    plan: String,
    plan_file: String,
    plan_disposition: &'static str,
    before: StoreRepackAccountingReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<StoreRepackAccountingReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    removed_packs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replayed: Option<bool>,
}

#[derive(Clone, Copy, Serialize)]
struct StoreRepackAccountingReport {
    generation: u64,
    logical_objects: u64,
    logical_bytes: u64,
    packs: u64,
    physical_bytes: u64,
}

impl From<PackedStorageAccounting> for StoreRepackAccountingReport {
    fn from(accounting: PackedStorageAccounting) -> Self {
        Self {
            generation: accounting.generation(),
            logical_objects: accounting.logical_objects(),
            logical_bytes: accounting.logical_bytes(),
            packs: accounting.packs(),
            physical_bytes: accounting.physical_bytes(),
        }
    }
}

pub(super) fn run_store_repack(
    args: &StoreRepackArgs,
    format: OutputFormat,
) -> Result<String, CliError> {
    validate_repack_paths(args)?;
    let node = StoreNodeId::new(args.node.clone())
        .map_err(|error| usage_error(format!("invalid packed node ID: {error}")))?;
    let (graph, maintenance) = load_campaign_store_maintenance_observational(&args.store)?;
    let capability = select_packed_repack(&maintenance, &node)?;
    let configuration = graph.configuration_id();

    let report = match args.operation {
        StoreRepackCommand::Plan => {
            let plan = capability.plan_repack().map_err(|error| {
                repack_error(format!("packed-store repack planning failed: {error}"))
            })?;
            let disposition = persist_plan(&args.plan, &plan)?;
            StoreRepackReport {
                schema: STORE_REPACK_REPORT_SCHEMA,
                operation: "plan",
                configuration: encode_configuration(configuration),
                node: node.as_str().to_owned(),
                plan: encode_plan_id(plan.id()),
                plan_file: args.plan.display().to_string(),
                plan_disposition: match disposition {
                    PlanDisposition::Created => "created",
                    PlanDisposition::Existing => "existing",
                },
                before: plan.before().into(),
                after: None,
                removed_packs: None,
                replayed: None,
            }
        }
        StoreRepackCommand::Apply => {
            let (plan_file, plan) = open_plan(&args.plan)?;
            sync_plan_basis(&plan_file, &args.plan)?;
            let result = capability.apply_repack(&plan).map_err(|error| {
                repack_error(format!("packed-store repack apply failed: {error}"))
            })?;
            StoreRepackReport {
                schema: STORE_REPACK_REPORT_SCHEMA,
                operation: "apply",
                configuration: encode_configuration(configuration),
                node: node.as_str().to_owned(),
                plan: encode_plan_id(result.plan()),
                plan_file: args.plan.display().to_string(),
                plan_disposition: "opened",
                before: result.before().into(),
                after: Some(result.after().into()),
                removed_packs: Some(result.removed_packs()),
                replayed: Some(result.replayed()),
            }
        }
    };

    render_store_repack(&report, format)
}

fn select_packed_repack<'a>(
    maintenance: &'a crucible_daemon::campaign_store_composition::StoreGraphAdmin,
    node: &StoreNodeId,
) -> Result<StoreGraphPackedRepackAdmin<'a>, CliError> {
    maintenance
        .packed_repack()
        .into_iter()
        .find(|capability| capability.node() == node)
        .ok_or_else(|| {
            repack_error(format!(
                "configured store node `{}` is not a packed repack boundary",
                node.as_str()
            ))
        })
}

fn persist_plan(path: &Path, plan: &PackedRepackPlan) -> Result<PlanDisposition, CliError> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    match open(path, flags, Mode::RUSR | Mode::WUSR) {
        Ok(descriptor) => {
            let mut file = File::from(descriptor);
            file.write_all(&plan.canonical_bytes())
                .map_err(|error| plan_file_error("write", path, error))?;
            file.sync_all()
                .map_err(|error| plan_file_error("sync", path, error))?;
            sync_parent(path)?;
            Ok(PlanDisposition::Created)
        }
        Err(error) if error == rustix::io::Errno::EXIST => {
            let (existing_file, existing) = open_plan(path)?;
            if existing != *plan {
                return Err(repack_error(
                    "packed-store repack plan file contains another exact plan",
                ));
            }
            sync_plan_basis(&existing_file, path)?;
            Ok(PlanDisposition::Existing)
        }
        Err(error) => Err(plan_file_error(
            "create",
            path,
            std::io::Error::from_raw_os_error(error.raw_os_error()),
        )),
    }
}

fn open_plan(path: &Path) -> Result<(File, PackedRepackPlan), CliError> {
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        plan_file_error(
            "open",
            path,
            std::io::Error::from_raw_os_error(error.raw_os_error()),
        )
    })?;
    let mut file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|error| plan_file_error("inspect", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(repack_error(
            "packed-store repack plan path is not a regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(MAXIMUM_REPACK_PLAN_BYTES);
    (&mut file)
        .take((MAXIMUM_REPACK_PLAN_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| plan_file_error("read", path, error))?;
    if bytes.len() > MAXIMUM_REPACK_PLAN_BYTES {
        return Err(repack_error(
            "packed-store repack plan exceeds its fixed byte limit",
        ));
    }
    let plan = PackedRepackPlan::from_canonical_bytes(&bytes)
        .map_err(|error| repack_error(format!("packed-store repack plan is invalid: {error}")))?;
    Ok((file, plan))
}

fn sync_plan_basis(file: &File, path: &Path) -> Result<(), CliError> {
    file.sync_all()
        .map_err(|error| plan_file_error("sync", path, error))?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| usage_error("packed-store repack plan path has no containing directory"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| plan_file_error("sync parent for", path, error))
}

fn validate_repack_paths(args: &StoreRepackArgs) -> Result<(), CliError> {
    for (label, path) in [
        ("store", args.store.as_path()),
        ("plan", args.plan.as_path()),
    ] {
        let normalized = path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
        if !path.is_absolute()
            || !normalized
            || path.as_os_str().as_bytes().contains(&0)
            || path.as_os_str().as_bytes().len() > MAXIMUM_REPACK_PATH_BYTES
        {
            return Err(usage_error(format!(
                "packed-store repack {label} path must be absolute, canonical, and at most 4095 bytes"
            )));
        }
    }
    if args.store == args.plan {
        return Err(usage_error(
            "packed-store repack store and plan paths must be distinct",
        ));
    }
    Ok(())
}

fn render_store_repack(
    report: &StoreRepackReport,
    format: OutputFormat,
) -> Result<String, CliError> {
    match format {
        OutputFormat::Jsonl => serde_json::to_string(report)
            .map_err(|error| repack_error(format!("store repack JSON encoding failed: {error}"))),
        OutputFormat::Json => serde_json::to_string_pretty(report)
            .map_err(|error| repack_error(format!("store repack JSON encoding failed: {error}"))),
        OutputFormat::Table => {
            let mut lines = vec![
                format!("{:<20} {}", "operation", report.operation),
                format!("{:<20} {}", "configuration", report.configuration),
                format!("{:<20} {}", "node", report.node),
                format!("{:<20} {}", "plan", report.plan),
                format!("{:<20} {}", "plan-file", report.plan_file),
                format!("{:<20} {}", "plan-disposition", report.plan_disposition),
                accounting_line("before", report.before),
            ];
            if let Some(after) = report.after {
                lines.push(accounting_line("after", after));
            }
            if let Some(removed) = report.removed_packs {
                lines.push(format!("{:<20} {removed}", "removed-packs"));
            }
            if let Some(replayed) = report.replayed {
                lines.push(format!("{:<20} {replayed}", "replayed"));
            }
            Ok(lines.join("\n"))
        }
        OutputFormat::Markdown => {
            let mut lines = vec![
                String::from("| field | value |"),
                String::from("|---|---|"),
                format!("| operation | {} |", report.operation),
                format!("| configuration | `{}` |", report.configuration),
                format!("| node | `{}` |", report.node),
                format!("| plan | `{}` |", report.plan),
                format!("| plan file | `{}` |", report.plan_file),
                format!("| plan disposition | {} |", report.plan_disposition),
                accounting_markdown("before", report.before),
            ];
            if let Some(after) = report.after {
                lines.push(accounting_markdown("after", after));
            }
            if let Some(removed) = report.removed_packs {
                lines.push(format!("| removed packs | {removed} |"));
            }
            if let Some(replayed) = report.replayed {
                lines.push(format!("| replayed | {replayed} |"));
            }
            Ok(lines.join("\n"))
        }
    }
}

fn accounting_line(label: &str, accounting: StoreRepackAccountingReport) -> String {
    format!(
        "{label:<20} generation={} logical-objects={} logical-bytes={} packs={} physical-bytes={}",
        accounting.generation,
        accounting.logical_objects,
        accounting.logical_bytes,
        accounting.packs,
        accounting.physical_bytes,
    )
}

fn accounting_markdown(label: &str, accounting: StoreRepackAccountingReport) -> String {
    format!(
        "| {label} | generation {} / {} logical objects / {} logical bytes / {} packs / {} physical bytes |",
        accounting.generation,
        accounting.logical_objects,
        accounting.logical_bytes,
        accounting.packs,
        accounting.physical_bytes,
    )
}

fn encode_configuration(configuration: StoreGraphConfigurationId) -> String {
    encode_bytes(&configuration.as_bytes())
}

fn encode_plan_id(plan: PackedRepackPlanId) -> String {
    encode_bytes(&plan.as_bytes())
}

fn encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn plan_file_error(operation: &str, path: &Path, error: std::io::Error) -> CliError {
    repack_error(format!(
        "packed-store repack plan {operation} failed for {}: {error}",
        path.display()
    ))
}

fn repack_error(message: impl Into<String>) -> CliError {
    backend_error(message.into())
}
