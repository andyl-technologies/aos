//! Typed retained installation, process, domain and current-publication inputs.
//!
//! These records describe actual captured values. Their hashes do not establish
//! authority: assembly separately verifies current Direct acceptance, installed
//! cohort membership, Clock MACs and the source-owned provider journal projection.

use std::{collections::BTreeMap, path::PathBuf};

use aos_hub_core::{
    direct_upload::DirectProtectedExternalProfile,
    storage_authority::{
        control::StorageAuthorityPublication,
        lease::{LeaseCohort, LeaseInteger, control::IssuerInstallation},
    },
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TupleFile {
    pub file: PathBuf,
    pub sha256: String,
    pub byte_size: u64,
    pub store_path: PathBuf,
    pub deriver: PathBuf,
}

/// Reopens the finite installed tuple instead of treating a selected hash as installation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ArtifactManifest {
    pub version: u32,
    pub common_source_store_path: PathBuf,
    pub worker_source_store_path: PathBuf,
    pub native_source_store_path: PathBuf,
    pub worker_distribution_store_path: PathBuf,
    pub worker_source_digest: String,
    pub worker_script_version: String,
    pub native_serving_role: String,
    pub native_serving: TupleFile,
    pub normal_native: TupleFile,
    pub wasm: TupleFile,
    pub script: TupleFile,
    pub runner: TupleFile,
    pub runtime_executable: TupleFile,
    pub provider_conformance: TupleFile,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NativeObservation {
    pub version: u32,
    pub role: String,
    pub pid: u32,
    pub start_ticks: String,
    pub owner_uid: u32,
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    pub command_line_sha256: String,
    pub common_source_store_path: PathBuf,
    pub worker_source_store_path: PathBuf,
    pub serving_store_path: PathBuf,
    pub serving_deriver: PathBuf,
    pub input_sha256: String,
    pub readiness_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Namespace {
    pub version: u32,
    pub observation_scope: String,
    pub observed_at: String,
    pub runner_pid: u32,
    pub runner_start_ticks: String,
    pub configuration_sha256: String,
    pub runner_sha256: String,
    pub isolation_module_sha256: String,
    pub miniflare_module_sha256: String,
    pub script_sha256: String,
    pub application_worker_name: String,
    pub source_worker_name: String,
    pub source_trigger_exclusions: Vec<String>,
    pub persistence_root: PathBuf,
    pub namespaces: Vec<NamespaceEntry>,
    pub participating_isolate_identity: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NamespaceEntry {
    pub binding_name: String,
    pub class_name: String,
    pub worker_name: String,
    pub namespace_key: String,
    pub object_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ReadIdentity {
    Versioned,
    GuardedVersionless,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderContract {
    pub observation_sha256: String,
    pub read_identity: ReadIdentity,
    pub maximum_conditional_read_bytes: LeaseInteger,
    pub strong_conditional_read: bool,
    pub private_incomplete_upload: bool,
    pub completed_upload_rejects_late_parts: bool,
    pub checksum_enforced: bool,
    pub positive_complete_identity: bool,
    pub positive_empty_put_identity: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Domain {
    pub profile: DirectProtectedExternalProfile,
    pub list_cohort: LeaseCohort,
    pub issuer_installation: IssuerInstallation,
    pub provider_contract: ProviderContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MirrorConfig {
    pub version: u8,
    pub domains: Vec<Domain>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListExport {
    pub version: u8,
    pub publication: StorageAuthorityPublication,
    pub issuer_installation: IssuerInstallation,
    pub list_cohort: LeaseCohort,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ObjectConfig {
    pub version: u8,
    pub guard_namespace_id: String,
    pub executor_identity: String,
    pub issuer_key_id: String,
    pub issuer_public_key: String,
    pub timing_profile: aos_hub_core::storage_authority::lease::LeaseTimingProfile,
    pub clock_uncertainty: i64,
    pub aliases: Vec<aos_hub_core::storage_authority::ApproveStorageAuthorityAlias>,
    pub cohorts: Vec<LeaseCohort>,
    pub publications: Vec<StorageAuthorityPublication>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProviderProjection {
    pub version: u8,
    pub report_sha256: String,
    pub original_sha256: String,
    pub executable_sha256: String,
    pub endpoint: String,
    pub bucket: String,
    pub private_staging_prefix: String,
    pub private_policy: aos_hub_core::direct_upload::DirectPrivateStagePolicyRef,
    pub policy_review_sha256: String,
    pub provider_contract: ProjectedContract,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectedContract {
    pub contract_id: String,
    pub evidence_digest: String,
    pub versioned_conditional_range_read: bool,
    pub versioned_multipart_complete: bool,
    pub private_incomplete_upload: bool,
    pub completed_upload_rejects_late_parts: bool,
    pub abort_closes_upload_id: bool,
    pub upload_part_checksum_enforced: bool,
    pub versioned_empty_put: bool,
    pub maximum_copy_read_range_bytes: String,
    pub protected_versionless: ProjectedVersionless,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProjectedVersionless {
    pub strong_conditional_range_read: bool,
    pub positive_multipart_complete: bool,
}

pub(super) type ReviewerKeys = BTreeMap<String, String>;
