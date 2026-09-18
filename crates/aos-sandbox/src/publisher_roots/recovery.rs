//! Fail-closed root reopen and retirement classification.

use std::collections::BTreeMap;

use super::{
    PublicationRootId, PublicationRootObligationsV1, PublicationRootRecordV1,
    PublicationRootRegistry, PublicationRootStateV1,
};

/// Selects the only legal recovery action for one root head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootRecoveryDispositionV1 {
    /// An active head must await fresh descriptor/service observation.
    AwaitFreshCustody,
    /// Current custody may serve new operations after exact re-pairing.
    ReopenActive,
    /// A draining head and all obligations must remain retained.
    RetainDraining,
    /// A drained head can advance to retired after custody is dropped.
    EligibleForRetirement,
    /// A retired head has no live custody or obligations.
    Retired,
    /// Retired state contradicts observed custody or retained obligations.
    Poison,
}

/// Classifies one current root head without carrying physical identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRecoveryEntryV1 {
    /// Logical root identity.
    pub root_id: PublicationRootId,
    /// Exact protected generation.
    pub generation: u64,
    /// Exact protected head digest.
    pub record_digest: aos_sandbox_core::ObjectDigest,
    /// Retained obligations used for the decision.
    pub obligations: PublicationRootObligationsV1,
    /// Closed recovery disposition.
    pub disposition: RootRecoveryDispositionV1,
}

/// Owns a deterministic sorted root recovery report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRecoveryReportV1 {
    /// One entry per supplied protected root head, sorted by identity.
    pub entries: Vec<RootRecoveryEntryV1>,
    /// Whether any contradiction requires authority poisoning.
    pub poisoned: bool,
}

/// Reduces protected heads with registry-owned obligations and live custody.
///
/// # Errors
///
/// Returns [`super::PublicationRootRegistryError`] for an unknown root or an
/// invalid registry lookup.
pub fn reduce_root_recovery_v1(
    registry: &PublicationRootRegistry,
    ledger: &crate::publisher_admission::AdmissionLedger,
    roots: impl IntoIterator<Item = PublicationRootId>,
) -> Result<RootRecoveryReportV1, super::PublicationRootRegistryError> {
    let mut unique = BTreeMap::<PublicationRootId, &PublicationRootRecordV1>::new();
    for root_id in roots {
        let record = registry
            .head(root_id)
            .ok_or(super::PublicationRootRegistryError::Absent)?;
        unique.insert(root_id, record);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(unique.len())
        .map_err(|_| super::PublicationRootRegistryError::Capacity)?;
    let mut poisoned = false;
    for (root_id, record) in unique {
        let retained = ledger.root_obligations(root_id);
        let observed = registry.has_live_custody(root_id);
        let disposition = match (record.state, observed, retained.blocks_retirement()) {
            (PublicationRootStateV1::Active, true, _) => RootRecoveryDispositionV1::ReopenActive,
            (PublicationRootStateV1::Active, false, _) => {
                RootRecoveryDispositionV1::AwaitFreshCustody
            }
            (PublicationRootStateV1::Draining, _, true) => {
                RootRecoveryDispositionV1::RetainDraining
            }
            (PublicationRootStateV1::Draining, true, false) => {
                RootRecoveryDispositionV1::RetainDraining
            }
            (PublicationRootStateV1::Draining, false, false) => {
                RootRecoveryDispositionV1::EligibleForRetirement
            }
            (PublicationRootStateV1::Retired, false, false) => RootRecoveryDispositionV1::Retired,
            (PublicationRootStateV1::Retired, _, _) => {
                poisoned = true;
                RootRecoveryDispositionV1::Poison
            }
        };
        entries.push(RootRecoveryEntryV1 {
            root_id,
            generation: record.generation,
            record_digest: record.record_digest,
            obligations: retained,
            disposition,
        });
    }
    Ok(RootRecoveryReportV1 { entries, poisoned })
}
