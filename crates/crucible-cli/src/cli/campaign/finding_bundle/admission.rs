//! One-time authored RAM archive admission and legitimate closed no-RAM work.
//!
//! A policy grants an independent archive namespace before input or output
//! effects. Absence selects explicit unavailable RAM admission once; it never
//! recovers from a rejected genuine grant or creates a source account implicitly.
//!
//! ```toml
//! version = 1
//! lifetime_ms = 60000
//! [resources]
//! # Complete HostOwnerResourcesDeployment fields are required.
//! [host_operation_budgets.preparation]
//! poll_interval_ms = 10
//! total_timeout_ms = 60000
//! # The remaining thirteen classes are required.
//! [input]
//! root = "/operator-installed/input"
//! project_id = 42
//! maximum_physical_bytes = 1073741824
//! maximum_inodes = 65536
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crucible_api::host_operational::HostOperationClass;
use crucible_campaign::{CampaignArchivePlan, CampaignRamAdmission, CampaignRepository};
use crucible_daemon::campaign_store_quota::CampaignArchiveNamespace;
use crucible_session::engine::owned_decode::{DecodeBudget, DecodeScope};
use serde::Deserialize;

use super::*;
use crate::cli_campaign::transfer_supervision::StandaloneArchiveOperation;

// The same bounded text-file allowance used for guarded executor policies;
// config parsing precedes admission and is not retroactively charged to it.
const MAX_ARCHIVE_POLICY_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchivePolicy {
    version: u32,
    lifetime_ms: u64,
    resources: crate::cli_verify_serve::HostOwnerResourcesDeployment,
    host_operation_budgets: BTreeMap<String, crate::cli_verify_serve::OperationBudgetDeployment>,
    input: Option<ArchiveProject>,
    output: Option<ArchiveProject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveProject {
    root: PathBuf,
    project_id: u32,
    maximum_physical_bytes: u64,
    maximum_inodes: u64,
}

pub(super) struct ArchiveBundleAdmission {
    input: Option<CampaignArchiveNamespace>,
    output: Option<CampaignArchiveNamespace>,
    // Namespaces and all borrowed decode owners close before this primary service.
    operation: Option<StandaloneArchiveOperation>,
}

impl ArchiveBundleAdmission {
    pub(super) fn open(
        policy: Option<&Path>,
        class: HostOperationClass,
        old_timeout_ms: Option<u64>,
        input: Option<&Path>,
        output: Option<&Path>,
    ) -> Result<Self, CliError> {
        let Some(policy) = policy else {
            let operation = old_timeout_ms
                .map(|timeout| StandaloneArchiveOperation::start(class, timeout))
                .transpose()?;
            return Ok(Self {
                input: None,
                output: None,
                operation,
            });
        };
        let bytes =
            read_bounded_bytes(policy, "archive resource policy", MAX_ARCHIVE_POLICY_BYTES)?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| usage_error("archive policy is not UTF-8"))?;
        let policy: ArchivePolicy = toml::from_str(text)
            .map_err(|error| usage_error(format!("invalid archive resource policy: {error}")))?;
        if policy.version != 1 || policy.lifetime_ms == 0 {
            return Err(usage_error(
                "archive policy requires version 1 and a positive lifetime",
            ));
        }
        let lifetime = old_timeout_ms.map_or(policy.lifetime_ms, |old| old.min(policy.lifetime_ms));
        let budgets = crate::cli_verify_serve::deployed_budgets(&policy.host_operation_budgets)?;
        let operation = StandaloneArchiveOperation::start_with_quota(
            class,
            budgets,
            Duration::from_millis(lifetime),
            policy.resources.resources(),
        )?;
        let mut admitted = Self {
            input: None,
            output: None,
            operation: Some(operation),
        };
        if let Some(input) = input {
            let project = policy
                .input
                .ok_or_else(|| usage_error("archive policy lacks the input project"))?;
            let expected = std::fs::canonicalize(input)?;
            admitted.input = Some(admitted.bind_project(project, &expected)?);
        }
        if let Some(output) = output {
            let project = policy
                .output
                .ok_or_else(|| usage_error("archive policy lacks the output project"))?;
            let parent = output
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let expected = std::fs::canonicalize(parent)?;
            admitted.output = Some(admitted.bind_project(project, &expected)?);
        }
        Ok(admitted)
    }

    fn bind_project(
        &self,
        project: ArchiveProject,
        expected: &Path,
    ) -> Result<CampaignArchiveNamespace, CliError> {
        if !project.root.is_absolute() || project.root != expected {
            return Err(usage_error(
                "archive project root must equal the canonical input or output parent",
            ));
        }
        let operation = self
            .operation
            .as_ref()
            .ok_or_else(|| usage_error("archive project has no original operation"))?;
        operation
            .original_operation()
            .bind_archive_namespace(
                &project.root,
                project.project_id,
                project.maximum_physical_bytes,
                project.maximum_inodes,
            )
            .map_err(CliError::ProviderAdmission)
    }

    pub(super) fn boundary(
        &self,
    ) -> Result<(), crucible_daemon::campaign_store_composition::CampaignArchiveBoundaryError> {
        if let Some(operation) = &self.operation {
            operation.boundary()?;
        }
        for namespace in [&self.input, &self.output].into_iter().flatten() {
            namespace.original().verify_live().map_err(|source| {
                crucible_daemon::campaign_store_composition::CampaignArchiveBoundaryError::from_admission(namespace.original(), source)
            })?;
        }
        Ok(())
    }

    pub(super) fn input_scope(&self) -> Result<Option<DecodeScope>, CliError> {
        self.input
            .as_ref()
            .map(|namespace| {
                namespace
                    .original()
                    .child()
                    .map(|child| child.enter())
                    .map_err(CliError::MetadataAdmission)
            })
            .transpose()
    }

    pub(super) fn input_path<'a>(&'a self, fallback: &'a Path) -> &'a Path {
        self.input
            .as_ref()
            .map_or(fallback, CampaignArchiveNamespace::root)
    }

    pub(super) fn input_repository(&self, root: &Path) -> Result<CampaignRepository, CliError> {
        match &self.input {
            Some(namespace) => namespace
                .open_repository(root)
                .map_err(|source| CliError::ProviderAdmission(source.into())),
            None => Ok(archive_repository(root, CampaignRamAdmission::Unavailable)),
        }
    }

    pub(super) fn require_output(&self, plan: &CampaignArchivePlan) -> Result<(), CliError> {
        if !plan.ram_roots().is_empty() && self.output.is_none() {
            return Err(CliError::ProviderAdmission(
                crucible_daemon::campaign_store_composition::StoreError::Unsupported {
                    capability: "authored-ram-archive-output-project",
                }
                .into(),
            ));
        }
        Ok(())
    }

    pub(super) fn output_repository(&self, root: &Path) -> Result<CampaignRepository, CliError> {
        match &self.output {
            Some(namespace) => namespace
                .open_repository(root)
                .map_err(|source| CliError::ProviderAdmission(source.into())),
            None => Ok(archive_repository(root, CampaignRamAdmission::Unavailable)),
        }
    }

    pub(super) fn output_original(&self) -> Option<&DecodeBudget> {
        self.output.as_ref().map(CampaignArchiveNamespace::original)
    }

    pub(super) fn prepare_output_directory(&self, path: &Path) -> Result<(), CliError> {
        self.publication_boundary()?;
        if let Some(output) = &self.output {
            output
                .prepare_directory(path)
                .map_err(|source| CliError::ProviderAdmission(source.into()))?;
        }
        Ok(())
    }

    pub(super) fn publication_boundary(&self) -> Result<(), CliError> {
        self.boundary()
            .map_err(|source| CliError::CampaignArchive(source.into()))?;
        if let Some(output) = &self.output {
            output
                .verify()
                .map_err(|source| CliError::ProviderAdmission(source.into()))?;
        }
        Ok(())
    }

    pub(super) fn original_operation(
        &self,
    ) -> Result<&crucible_daemon::campaign_store_composition::CampaignArchiveHostOperation, CliError>
    {
        self.operation
            .as_ref()
            .map(StandaloneArchiveOperation::original_operation)
            .ok_or_else(|| usage_error("branch execution requires an original operation"))
    }

    pub(super) fn complete(&self) -> Result<(), CliError> {
        self.publication_boundary()?;
        if let Some(operation) = &self.operation {
            operation.complete()?;
        }
        Ok(())
    }
}
