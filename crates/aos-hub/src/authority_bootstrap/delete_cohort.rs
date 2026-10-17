//! Read-only selection of a delete-only cohort from reviewed SQL authority.
//!
//! `delete-cohort.json` retains the actual publication, configured issuer and
//! narrowed cohort. It supplies no capability result, credential material,
//! signing permission, GC claim or provider-dispatch authority.
//!
//! The outer document contains complete existing canonical protocol records:
//!
//! ```text
//! DeleteCohortExport {
//!     version: 1,
//!     publication: StorageAuthorityPublication,
//!     issuer_installation: IssuerInstallation,
//!     delete_cohort: LeaseCohort,
//! }
//! ```

use std::path::Path;

use anyhow::{Result, ensure};
use aos_hub::authority_server::AuthorityConfiguration;
use aos_hub_core::{
    db::Database,
    storage_authority::{
        PhysicalStorageAuthorityId,
        control::StorageAuthorityPublication,
        lease::{LeaseCohort, LeaseEffect, LeasePurpose, control::IssuerInstallation},
    },
};
use serde::{Deserialize, Serialize};

/// Selects one delete-only cohort without admitting it to any executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteCohortExport {
    /// Closed selection document format, currently one.
    pub version: u8,
    /// Exact current admitted publication built by SQL.
    pub publication: StorageAuthorityPublication,
    /// Independently configured issuer; no signing key is read.
    pub issuer_installation: IssuerInstallation,
    /// Delete-only selection under the reviewed association and prefix.
    pub delete_cohort: LeaseCohort,
}

/// Exports a narrowed delete cohort from the actual admitted SQL publication.
///
/// The operator must separately install its independent provider contract and
/// obtain the real capability probe, current credential custody and GC claim.
/// The export does not contact an issuer or provider, read keys, mutate SQL,
/// resolve secrets or establish readiness.
///
/// # Errors
/// Rejects invalid configuration/history, foreign authority/issuer, missing or
/// denied/stale publication, unadmitted association or prefix, changed SQL head,
/// oversized documents, insecure/existing output, and database/filesystem errors.
pub async fn export_delete_cohort(
    db: &Database,
    authority_id: &PhysicalStorageAuthorityId,
    configuration: &AuthorityConfiguration,
    association_id: &str,
    admitted_prefix: &str,
    output: &Path,
) -> Result<DeleteCohortExport> {
    db.validate_binding_identity_reservations().await?;
    configuration.validate()?;
    let installation = &configuration.installation;
    ensure!(
        installation.authority.authority_id == *authority_id,
        "delete issuer authority differs"
    );
    let publication = db
        .storage_authority_publication(
            authority_id,
            &installation.authority.guard_namespace_id,
            &installation.executor_identity,
        )
        .await?;
    ensure!(
        publication.authority == installation.authority,
        "delete issuer installation differs"
    );
    let cohort = LeaseCohort::from_publication(
        &publication,
        &installation.executor_identity,
        association_id,
        LeasePurpose::Delete,
        admitted_prefix,
        vec![LeaseEffect::ConditionalDelete],
    )?;
    let selection = DeleteCohortExport {
        version: 1,
        publication: publication.clone(),
        issuer_installation: installation.clone(),
        delete_cohort: cohort,
    };
    let bytes = serde_json::to_vec(&selection)?;
    ensure!(
        bytes.len() <= super::MAX_DOCUMENT_BYTES,
        "oversized delete cohort export"
    );

    // A selection is an observed head, not a continuing permission. Refuse a
    // mixed export when any reviewed member or admission changes during assembly.
    ensure!(
        db.storage_authority_publication(
            authority_id,
            &installation.authority.guard_namespace_id,
            &installation.executor_identity,
        )
        .await?
            == publication,
        "delete cohort publication changed during export"
    );
    super::custody::publish_directory(output, &[("delete-cohort.json", bytes)])?;
    Ok(selection)
}
