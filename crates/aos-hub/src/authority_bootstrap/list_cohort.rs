//! Read-only selection of a list-only cohort from reviewed SQL authority.
//!
//! `list-cohort.json` retains the actual publication, configured issuer and
//! narrowed cohort. It supplies no capability result, credential material,
//! signing permission, storage-work plan or provider-dispatch authority.
//!
//! The outer document contains complete existing canonical protocol records:
//!
//! ```text
//! ListCohortExport {
//!     version: 1,
//!     publication: StorageAuthorityPublication,
//!     issuer_installation: IssuerInstallation,
//!     list_cohort: LeaseCohort,
//! }
//! ```

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub::authority_server::AuthorityConfiguration;
use aos_hub_core::{
    db::Database,
    storage_authority::{
        control::StorageAuthorityPublication,
        lease::{control::IssuerInstallation, LeaseCohort, LeaseEffect, LeasePurpose},
        PhysicalStorageAuthorityId,
    },
};
use serde::{Deserialize, Serialize};

/// Selects one list-only cohort without admitting it to any executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListCohortExport {
    /// Closed selection document format, currently one.
    pub version: u8,
    /// Exact current admitted publication built by SQL.
    pub publication: StorageAuthorityPublication,
    /// Independently configured issuer; no signing key is read.
    pub issuer_installation: IssuerInstallation,
    /// List-only selection under the reviewed association and prefix.
    pub list_cohort: LeaseCohort,
}

/// Exports a narrowed list cohort from the actual admitted SQL publication.
///
/// The operator must separately install its independent provider contract and
/// validate its current List credential and custody, and supply a bounded
/// storage-work plan.
/// The export does not contact an issuer or provider, read keys, mutate SQL,
/// resolve secrets or establish readiness.
///
/// # Errors
/// Rejects invalid configuration/history, foreign authority/issuer, missing or
/// denied/stale publication, unadmitted association or prefix, changed SQL head,
/// oversized documents, insecure/existing output, and database/filesystem errors.
pub async fn export_list_cohort(
    db: &Database,
    authority_id: &PhysicalStorageAuthorityId,
    configuration: &AuthorityConfiguration,
    association_id: &str,
    admitted_prefix: &str,
    output: &Path,
) -> Result<ListCohortExport> {
    db.validate_binding_identity_reservations().await?;
    configuration.validate()?;
    let installation = &configuration.installation;
    ensure!(
        installation.authority.authority_id == *authority_id,
        "list issuer authority differs"
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
        "list issuer installation differs"
    );
    let cohort = LeaseCohort::from_publication(
        &publication,
        &installation.executor_identity,
        association_id,
        LeasePurpose::List,
        admitted_prefix,
        vec![LeaseEffect::List],
    )?;
    let selection = ListCohortExport {
        version: 1,
        publication: publication.clone(),
        issuer_installation: installation.clone(),
        list_cohort: cohort,
    };
    let bytes = serde_json::to_vec(&selection)?;
    ensure!(
        bytes.len() <= super::MAX_DOCUMENT_BYTES,
        "oversized list cohort export"
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
        "list cohort publication changed during export"
    );
    super::custody::publish_directory(output, &[("list-cohort.json", bytes)])?;
    Ok(selection)
}
