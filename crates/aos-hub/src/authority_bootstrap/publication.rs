//! Read-only export of the exact reviewed SQL authority head in any admission state.
//!
//! `publication.json` carries the canonical control publication. The adjacent
//! `publication-receipt.json` commits to those bytes without adding execution
//! authority, credential material, delivery acknowledgement, or readiness.

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::db::Database;
use aos_hub_core::storage_authority::{PhysicalStorageAuthorityId, StorageAuthorityAdmissionState};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::custody;

/// Identifies the exact canonical publication exported from the reviewed SQL head.
#[derive(Debug, Serialize)]
pub struct PublicationExportReceipt {
    /// Closed export receipt format, currently one.
    pub version: u8,
    /// Permanent reviewed physical authority identity.
    pub authority_id: PhysicalStorageAuthorityId,
    /// Actual desired SQL admission generation.
    pub generation: i64,
    /// Canonical admission commitment retained in SQL.
    pub admission_digest: String,
    /// SHA-256 of the exact canonical `publication.json` bytes.
    pub publication_sha256: String,
    /// Actual desired admission lifecycle, including blocked and retired heads.
    pub state: StorageAuthorityAdmissionState,
}

/// Exports the current reviewed SQL publication without contacting an executor.
///
/// This operator-only path accepts blocked and retired heads without selecting
/// an association or deriving a cohort. Both files are durably published under
/// one new owner-private directory. It never resolves credentials, mutates SQL,
/// acknowledges delivery, or changes provider admission.
///
/// # Errors
/// Rejects invalid binding history, absent or changed reviewed heads, stale
/// admitted facts, mismatched executor or namespace, insecure output custody,
/// existing output, oversized documents, or database and filesystem failures.
pub async fn export_publication(
    db: &Database,
    authority_id: &PhysicalStorageAuthorityId,
    guard_namespace_id: &str,
    executor_identity: &str,
    output: &Path,
) -> Result<PublicationExportReceipt> {
    db.validate_binding_identity_reservations().await?;
    let publication = db
        .storage_authority_publication(authority_id, guard_namespace_id, executor_identity)
        .await?;
    let bytes = serde_json::to_vec(&publication)?;
    let receipt = PublicationExportReceipt {
        version: 1,
        authority_id: publication.authority.authority_id.clone(),
        generation: publication.generation,
        admission_digest: publication.digest.clone(),
        publication_sha256: hex::encode(Sha256::digest(&bytes)),
        state: publication.admission.state,
    };
    let receipt_bytes = serde_json::to_vec(&receipt)?;

    // The export is evidence of an observed SQL head, not a lasting permit.
    // Re-read current facts after serialization so no mixed or superseded head
    // is published when a reviewed decision changes during assembly.
    ensure!(
        db.storage_authority_publication(authority_id, guard_namespace_id, executor_identity)
            .await?
            == publication,
        "reviewed authority publication changed during export"
    );
    custody::publish_directory(
        output,
        &[
            ("publication.json", bytes),
            ("publication-receipt.json", receipt_bytes),
        ],
    )?;
    Ok(receipt)
}
