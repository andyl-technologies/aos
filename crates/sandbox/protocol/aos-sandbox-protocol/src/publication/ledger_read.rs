//! Validates historical publication selections against one borrowed ledger view.
//!
//! The shared engines preserve the established byte/schema checks and ordering.
//! They perform no IO, authenticate no protected Journal or signer, and select
//! no executable authority. Native owners must separately preserve their actual
//! protected-prefix, name, exclusive-borrow and currentness obligations.

use aos_sandbox_model::{ObjectDigest, RecordNamespace, SandboxId};
use aos_sandbox_ownership_protocol::OwnershipClaimV1;

use super::{
    AuthorityPublicationDraftV1, CURRENT_KEY_PREFIX, DecodedPublicationCurrentV1,
    PREPARED_KEY_PREFIX, PublicationHistoryError, current_key, decode_current,
    decode_prepared, prepared_key,
};
use crate::domain_ledger::readonly::{HistoricalLedgerReadViewV1, HistoricalLedgerComparisonV2};

/// Reports historical publication DATA or actual recorded native poison.
#[derive(Debug, thiserror::Error)]
pub enum PublicationLedgerDataErrorV1 {
    /// The actual borrowed native owner records ambiguous mutation state.
    #[error("historical publication native ledger is poisoned")]
    Poisoned,
    /// The established canonical publication parser or structural join refused.
    #[error(transparent)]
    Publication(#[from] PublicationHistoryError),
}

fn ensure_unpoisoned(
    view: HistoricalLedgerComparisonV2<'_>,
) -> Result<(), PublicationLedgerDataErrorV1> {
    if view.native_poisoned_v2() {
        Err(PublicationLedgerDataErrorV1::Poisoned)
    } else {
        Ok(())
    }
}

/// Resolves and checks the historical current selection from an already-scanned view.
///
/// # Errors
///
/// Rejects actual recorded poison, noncanonical bytes or inconsistent historical links.
pub fn current_in_validated_namespace(
    journal: HistoricalLedgerReadViewV1<'_>,
    sandbox: SandboxId,
) -> Result<Option<DecodedPublicationCurrentV1>, PublicationLedgerDataErrorV1> {
    current_in_validated_namespace_comparison_v2(HistoricalLedgerComparisonV2::Native(journal), sandbox)
}

pub(crate) fn current_in_validated_namespace_comparison_v2(
    journal: HistoricalLedgerComparisonV2<'_>,
    sandbox: SandboxId,
) -> Result<Option<DecodedPublicationCurrentV1>, PublicationLedgerDataErrorV1> {
    ensure_unpoisoned(journal)?;
    let current = journal
        .get(RecordNamespace::AuthorityPublication, &current_key(sandbox))
        .map(decode_current)
        .transpose()?;
    let Some(current) = current else {
        return Ok(None);
    };
    if current.history.sandbox() != sandbox {
        return Err(PublicationHistoryError::CorruptCurrent.into());
    }
    let prepared = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(current.history.digest()),
        )
        .map(|bytes| decode_prepared(bytes, current.history.digest()))
        .transpose()?
        .ok_or(PublicationHistoryError::CorruptCurrent)?;
    if prepared != current.history {
        return Err(PublicationHistoryError::CorruptCurrent.into());
    }
    Ok(Some(current))
}

/// Checks a historical activated gate against its publication and successor.
///
/// # Errors
///
/// Rejects actual recorded poison, noncanonical bytes or inconsistent historical links.
pub fn validate_durable_gate_publication(
    journal: HistoricalLedgerReadViewV1<'_>,
    publication_digest: ObjectDigest,
    draft: &AuthorityPublicationDraftV1,
    claim: &OwnershipClaimV1,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), PublicationLedgerDataErrorV1> {
    validate_durable_gate_publication_comparison_v2(HistoricalLedgerComparisonV2::Native(journal), publication_digest, draft, claim, lease_generation, lease_digest)
}

pub(crate) fn validate_durable_gate_publication_comparison_v2(
    journal: HistoricalLedgerComparisonV2<'_>,
    publication_digest: ObjectDigest,
    draft: &AuthorityPublicationDraftV1,
    claim: &OwnershipClaimV1,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), PublicationLedgerDataErrorV1> {
    ensure_unpoisoned(journal)?;
    let prepared = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &prepared_key(publication_digest),
        )
        .map(|bytes| decode_prepared(bytes, publication_digest))
        .transpose()?
        .ok_or(PublicationHistoryError::CorruptCurrent)?;
    let manifest = draft.manifest();
    let semantics = manifest.manifest();
    let assignment = claim.assignment();
    if prepared.sandbox() != assignment.sandbox()
        || *prepared.incarnation() != *assignment.incarnation().as_bytes()
        || prepared.epoch() != assignment.epoch().get()
        || prepared.desired_generation() != claim.desired_generation().get()
        || prepared.assignment_digest() != assignment.digest()
        || *prepared.node() != *claim.node().as_bytes()
        || prepared.source_draft_digest() != draft.digest()
        || prepared.lease_generation() != lease_generation
        || prepared.lease_digest() != lease_digest
        || prepared.receipt_authority() != draft.ownership_authority()
        || prepared.receipt_action() != claim.action()
        || *prepared.receipt_request_id() != *claim.request_id()
        || prepared.receipt_claim_digest() != claim.digest()
        || semantics.sandbox() != assignment.sandbox()
    {
        return Err(PublicationHistoryError::CorruptCurrent.into());
    }
    let current = journal
        .get(
            RecordNamespace::AuthorityPublication,
            &current_key(assignment.sandbox()),
        )
        .map(decode_current)
        .transpose()?
        .ok_or(PublicationHistoryError::CorruptCurrent)?;
    prepared
        .require_successor(&current.history)
        .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
    Ok(())
}

/// Scans the complete historical publication namespace and optional subject.
///
/// # Errors
///
/// Rejects actual recorded poison, noncanonical bytes or inconsistent historical links.
pub fn scan_publication_namespace(
    journal: HistoricalLedgerReadViewV1<'_>,
    subject: Option<SandboxId>,
) -> Result<bool, PublicationLedgerDataErrorV1> {
    scan_publication_namespace_comparison_v2(HistoricalLedgerComparisonV2::Native(journal), subject)
}

pub(crate) fn scan_publication_namespace_comparison_v2(
    journal: HistoricalLedgerComparisonV2<'_>,
    subject: Option<SandboxId>,
) -> Result<bool, PublicationLedgerDataErrorV1> {
    let mut present = false;
    // Diagnostic materialized values can lag an ambiguously committed successor.
    // Never turn that stale snapshot into current publication or replay evidence.
    ensure_unpoisoned(journal)?;
    for (key, value) in journal.records(RecordNamespace::AuthorityPublication) {
        if let Some(suffix) = key.strip_prefix(CURRENT_KEY_PREFIX) {
            let sandbox_bytes: [u8; 16] = suffix
                .try_into()
                .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
            let sandbox = SandboxId::from_bytes(sandbox_bytes);
            let current = decode_current(value)?;
            present |= subject == Some(current.history.sandbox());
            if current.history.sandbox() != sandbox {
                return Err(PublicationHistoryError::CorruptCurrent.into());
            }
            let permanent = journal
                .get(
                    RecordNamespace::AuthorityPublication,
                    &prepared_key(current.history.digest()),
                )
                .map(|bytes| decode_prepared(bytes, current.history.digest()))
                .transpose()?
                .ok_or(PublicationHistoryError::CorruptCurrent)?;
            if permanent != current.history {
                return Err(PublicationHistoryError::CorruptCurrent.into());
            }
        } else if let Some(suffix) = key.strip_prefix(PREPARED_KEY_PREFIX) {
            let digest_bytes: [u8; 32] = suffix
                .try_into()
                .map_err(|_| PublicationHistoryError::CorruptCurrent)?;
            let prepared = decode_prepared(value, ObjectDigest::from_bytes(digest_bytes))?;
            present |= subject == Some(prepared.sandbox());
        } else {
            return Err(PublicationHistoryError::CorruptCurrent.into());
        }
    }
    Ok(present)
}

/// Selects current publication DATA from supplied fully validated rows.
///
/// The caller must retain its genuine full native/schema/crosslink interval;
/// rows cannot establish currentness, a writer, a lease or effect authority.
///
/// # Errors
/// Rejects the same corrupt current pointer, immutable prepared record or
/// complete canonical publication as the existing Journal selector.
pub fn current_rows_data_v2(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    sandbox: SandboxId,
) -> Result<Option<DecodedPublicationCurrentV1>, PublicationLedgerDataErrorV1> {
    current_in_validated_namespace_comparison_v2(HistoricalLedgerComparisonV2::Rows(rows), sandbox)
}

/// Scans the complete supplied publication namespace with the canonical recipe.
///
/// Native callers retain the actual health/currentness and complete-prefix
/// observations before entering. Supplied rows cannot establish those facts.
///
/// # Errors
/// Refuses the same malformed keys, immutable records and current/prepared
/// crosslinks as the existing historical native view.
pub fn scan_namespace_rows_data_v2(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    subject: Option<SandboxId>,
) -> Result<bool, PublicationLedgerDataErrorV1> {
    scan_publication_namespace_comparison_v2(HistoricalLedgerComparisonV2::Rows(rows), subject)
}

/// Compares one activated gate with supplied complete publication history DATA.
///
/// Native health and protected ownership stay on the real caller before entry.
///
/// # Errors
/// Refuses the original gate, claim, current/prepared or successor mismatch.
pub fn validate_durable_gate_publication_rows_data_v2(
    rows: crate::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'_>,
    publication_digest: ObjectDigest,
    draft: &AuthorityPublicationDraftV1,
    claim: &OwnershipClaimV1,
    lease_generation: u64,
    lease_digest: ObjectDigest,
) -> Result<(), PublicationLedgerDataErrorV1> {
    validate_durable_gate_publication_comparison_v2(
        HistoricalLedgerComparisonV2::Rows(rows), publication_digest,
        draft, claim, lease_generation, lease_digest,
    )
}
