//! Canonical per-provider acquisition projection for inventory reconciliation.
//!
//! Projection entries are acquisition-ID sorted and contain only immutable
//! intent plus the exact provider facts needed to compare a signed Inventory.
//! Session replacement never changes this projection.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use aos_sandbox_source_provider_protocol::{
    InventoryLeaseStateV1, SignedSourceProviderInventoryV1, SourceProviderInventoryEntryV1,
};

use super::format::state_error;
use super::model::{
    ProjectionEntryV2, ProjectionExpectationV2, ProviderAttemptStateV2, ProviderScopeV2,
    ProviderStatusV2, ReconciliationV2, ReleaseProofV2, SourceAcquisitionEvidenceV2,
    SourceAcquisitionPhaseV2, SourceAcquisitionRowV2, SourceProviderHeadV2,
    SourceProviderQueryAttemptV2,
};
use crate::Result;

const PROJECTION_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-projection.v2\0";

pub(super) struct ProjectionV2 {
    pub count: u32,
    pub digest: [u8; 32],
}

pub(super) fn project_scope(
    scope: ProviderScopeV2,
    epoch: u64,
    rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
) -> Result<ProjectionV2> {
    let entries = rows
        .values()
        .filter(|row| row.scope == scope)
        .map(project_row)
        .collect::<Vec<_>>();
    if entries.is_empty() && epoch != 0 {
        return Err(state_error(
            "empty source-provider projection has a nonzero epoch",
        ));
    }
    if !entries.is_empty() && epoch == 0 {
        return Err(state_error(
            "nonempty source-provider projection has a zero epoch",
        ));
    }
    projection_from_entries(scope, epoch, &entries)
}

pub(super) fn projection_from_entries(
    scope: ProviderScopeV2,
    epoch: u64,
    entries: &[ProjectionEntryV2],
) -> Result<ProjectionV2> {
    if entries
        .windows(2)
        .any(|pair| pair[0].acquisition_id >= pair[1].acquisition_id)
        || entries
            .iter()
            .any(|entry| !projection_entry_is_closed(entry))
    {
        return Err(state_error(
            "source-provider projection entries are not strictly ordered",
        ));
    }
    let count = u32::try_from(entries.len())
        .map_err(|_| state_error("source-provider projection count exceeds u32"))?;
    let bytes = entries
        .iter()
        .map(|entry| {
            serde_json::to_vec(entry)
                .map_err(|_| state_error("cannot encode source-provider projection entry"))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut digest = Sha256::new();
    digest.update(PROJECTION_DOMAIN);
    digest.update(scope.holder_authority_id);
    digest.update(scope.provider_authority_id);
    digest.update(scope.route_id);
    digest.update(scope.resource_namespace_digest);
    digest.update(epoch.to_be_bytes());
    digest.update(count.to_be_bytes());
    for entry in bytes {
        let length = u32::try_from(entry.len())
            .map_err(|_| state_error("source-provider projection entry exceeds u32"))?;
        digest.update(length.to_be_bytes());
        digest.update(entry);
    }

    Ok(ProjectionV2 {
        count,
        digest: digest.finalize().into(),
    })
}

fn projection_entry_is_closed(entry: &ProjectionEntryV2) -> bool {
    if entry.acquisition_id == [0; 32]
        || entry.acquire_intent_digest == [0; 32]
        || entry.release_intent_digest == Some([0; 32])
        || entry.lease_id == Some([0; 16])
        || entry.signed_lease_digest == Some([0; 32])
        || entry.provider_resource_id == Some([0; 32])
        || entry.provider_resource_generation == Some(0)
        || entry.provider_resource_state_digest == Some([0; 32])
        || entry.provider_resource_digest == Some([0; 32])
        || entry.provider_catalog_generation == Some(0)
        || entry.provider_catalog_digest == Some([0; 32])
        || entry.provider_selection_generation == Some(0)
        || entry.provider_selection_digest == Some([0; 32])
        || entry
            .provider_proof_class
            .is_some_and(|value| !(1..=4).contains(&value))
        || entry.provider_proof_digest == Some([0; 32])
        || entry.release_generation == Some(0)
    {
        return false;
    }
    let evidence = [
        entry.lease_id.is_some(),
        entry.signed_lease_digest.is_some(),
        entry.provider_resource_id.is_some(),
        entry.provider_resource_generation.is_some(),
        entry.provider_resource_state_digest.is_some(),
        entry.provider_resource_digest.is_some(),
        entry.provider_catalog_generation.is_some(),
        entry.provider_catalog_digest.is_some(),
        entry.provider_selection_generation.is_some(),
        entry.provider_selection_digest.is_some(),
        entry.provider_proof_class.is_some(),
        entry.mount_proof_class.is_some(),
        entry.provider_proof_digest.is_some(),
    ];
    let has_evidence = evidence.iter().all(|value| *value);
    if evidence.iter().any(|value| *value) != has_evidence {
        return false;
    }
    match entry.expectation {
        ProjectionExpectationV2::AbsentOrMatchingActive => {
            !has_evidence
                && entry.release_intent_digest.is_none()
                && entry.release_generation.is_none()
        }
        ProjectionExpectationV2::MatchingActive => {
            has_evidence
                && entry.release_intent_digest.is_none()
                && entry.release_generation.is_none()
        }
        ProjectionExpectationV2::MatchingActiveOrReaping => {
            has_evidence
                && entry.release_intent_digest.is_some()
                && entry.release_generation.is_none()
        }
        ProjectionExpectationV2::MatchingReleasedOrAbsent => {
            has_evidence && entry.release_intent_digest.is_some()
        }
    }
}

pub(super) fn project_row(row: &SourceAcquisitionRowV2) -> ProjectionEntryV2 {
    let phase = effective_phase(row);
    let expectation = if row.release_proof.is_some() || phase == SourceAcquisitionPhaseV2::Released
    {
        ProjectionExpectationV2::MatchingReleasedOrAbsent
    } else if phase == SourceAcquisitionPhaseV2::Releasing {
        ProjectionExpectationV2::MatchingActiveOrReaping
    } else if row.evidence.is_some() {
        ProjectionExpectationV2::MatchingActive
    } else {
        ProjectionExpectationV2::AbsentOrMatchingActive
    };
    let release_generation = match row.release_proof.as_ref() {
        Some(ReleaseProofV2::ProviderReceipt {
            release_generation, ..
        }) => Some(*release_generation),
        _ => None,
    };

    ProjectionEntryV2 {
        acquisition_id: row.acquisition_id,
        acquire_intent_digest: row.acquire_intent_digest,
        release_intent_digest: row.release_intent_digest,
        expectation,
        lease_id: row.evidence.as_ref().map(|value| value.lease_id),
        signed_lease_digest: row.evidence.as_ref().map(|value| value.signed_lease_digest),
        provider_resource_id: row
            .evidence
            .as_ref()
            .map(|value| value.provider_resource_id),
        provider_resource_generation: row
            .evidence
            .as_ref()
            .map(|value| value.provider_resource_generation),
        provider_resource_state_digest: row.evidence.as_ref().map(|value| {
            value
                .historical_lease_signer
                .selection_floor
                .resource_digest
        }),
        provider_resource_digest: row
            .evidence
            .as_ref()
            .map(|value| value.provider_resource_digest),
        provider_catalog_generation: row
            .evidence
            .as_ref()
            .map(|value| value.provider_catalog_generation),
        provider_catalog_digest: row
            .evidence
            .as_ref()
            .map(|value| value.provider_catalog_digest),
        provider_selection_generation: row
            .evidence
            .as_ref()
            .map(|value| value.provider_selection_generation),
        provider_selection_digest: row
            .evidence
            .as_ref()
            .map(|value| value.provider_selection_digest),
        provider_proof_class: row
            .evidence
            .as_ref()
            .map(|value| value.provider_proof_class),
        mount_proof_class: row.evidence.as_ref().map(|value| value.proof_class),
        provider_proof_digest: row
            .evidence
            .as_ref()
            .map(|value| value.provider_proof_digest),
        release_generation,
    }
}

fn effective_phase(row: &SourceAcquisitionRowV2) -> SourceAcquisitionPhaseV2 {
    if row.phase == SourceAcquisitionPhaseV2::Faulted {
        row.faulted_from
            .unwrap_or(SourceAcquisitionPhaseV2::Faulted)
    } else {
        row.phase
    }
}

const RESIDUAL_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-inventory-residuals.v2\0";
const CONFLICT_DOMAIN: &[u8] = b"aos.sandbox.mount.source-provider-inventory-conflicts.v2\0";

pub(super) fn reproduce_reconciliation(
    head: &SourceProviderHeadV2,
    attempts: &BTreeMap<[u8; 32], SourceProviderQueryAttemptV2>,
    rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV2>,
) -> Result<ReconciliationV2> {
    let floor = head
        .inventory_floor
        .as_ref()
        .ok_or_else(|| state_error("reconciliation lacks an Inventory floor"))?;
    let attempt = attempts
        .get(&floor.attempt.id)
        .ok_or_else(|| state_error("reconciliation Inventory attempt is missing"))?;
    let ProviderAttemptStateV2::DispositionConsumed {
        status: ProviderStatusV2::Complete,
        signed_result,
        ..
    } = &attempt.state
    else {
        return Err(state_error(
            "reconciliation Inventory attempt is not Complete",
        ));
    };
    let inventory = SignedSourceProviderInventoryV1::from_canonical_bytes(signed_result)
        .map_err(|_| state_error("reconciliation Inventory is invalid"))?;
    let entries = inventory
        .subject()
        .entries()
        .iter()
        .map(|entry| (*entry.acquisition_id().as_bytes(), entry))
        .collect::<BTreeMap<_, _>>();
    let scope_rows = rows
        .values()
        .filter(|row| row.scope == head.scope)
        .map(|row| (row.acquisition_id, row))
        .collect::<BTreeMap<_, _>>();

    let residuals = entries
        .iter()
        .filter(|(id, _)| !scope_rows.contains_key(id))
        .map(|(id, entry)| DiagnosticV2 {
            acquisition_id: *id,
            reason: 1,
            entry_digest: inventory_entry_digest(entry),
        })
        .collect::<Vec<_>>();
    let conflicts = scope_rows
        .iter()
        .filter_map(|(id, row)| {
            let entry = entries.get(id).copied();
            reconciliation_conflict(row, entry).map(|reason| DiagnosticV2 {
                acquisition_id: *id,
                reason,
                entry_digest: entry.map_or([0; 32], inventory_entry_digest),
            })
        })
        .collect::<Vec<_>>();

    Ok(ReconciliationV2 {
        projection_epoch: head.current_projection_epoch,
        projection_digest: head.current_projection_digest,
        residual_count: u32::try_from(residuals.len())
            .map_err(|_| state_error("Inventory residual count exceeds u32"))?,
        residual_digest: diagnostics_digest(
            RESIDUAL_DOMAIN,
            head.scope,
            floor.attempt.id,
            &residuals,
        ),
        conflict_count: u32::try_from(conflicts.len())
            .map_err(|_| state_error("Inventory conflict count exceeds u32"))?,
        conflict_digest: diagnostics_digest(
            CONFLICT_DOMAIN,
            head.scope,
            floor.attempt.id,
            &conflicts,
        ),
    })
}

struct DiagnosticV2 {
    acquisition_id: [u8; 32],
    reason: u8,
    entry_digest: [u8; 32],
}

pub(super) fn reconciliation_conflict(
    row: &SourceAcquisitionRowV2,
    entry: Option<&SourceProviderInventoryEntryV1>,
) -> Option<u8> {
    let phase = effective_phase(row);
    if row.release_proof.is_some() || phase == SourceAcquisitionPhaseV2::Released {
        return match entry {
            None => None,
            Some(value)
                if value.state() == InventoryLeaseStateV1::Released
                    && row.evidence.as_ref().is_some_and(|evidence| {
                        inventory_entry_matches_evidence(value, evidence)
                    }) =>
            {
                None
            }
            Some(_) => Some(4),
        };
    }
    if phase == SourceAcquisitionPhaseV2::Releasing {
        return match entry {
            Some(value)
                if matches!(
                    value.state(),
                    InventoryLeaseStateV1::Active | InventoryLeaseStateV1::Reaping
                ) && row
                    .evidence
                    .as_ref()
                    .is_some_and(|evidence| inventory_entry_matches_evidence(value, evidence)) =>
            {
                None
            }
            _ => Some(3),
        };
    }
    match (&row.evidence, entry) {
        (None, None) => None,
        // A provider-side Active lease without local Complete evidence is an
        // indeterminate Acquire outcome, never evidence that local state is
        // already reconciled.
        (None, Some(_)) => Some(2),
        (Some(evidence), Some(value))
            if value.state() == InventoryLeaseStateV1::Active
                && inventory_entry_matches_evidence(value, evidence) =>
        {
            None
        }
        (Some(_), None) => Some(1),
        _ => Some(2),
    }
}

pub(super) fn inventory_entry_matches_evidence(
    entry: &SourceProviderInventoryEntryV1,
    evidence: &SourceAcquisitionEvidenceV2,
) -> bool {
    let resource = entry.resource();
    let proof_matches = entry.proof_class() == evidence.provider_proof_class;
    entry.lease_id() == evidence.lease_id
        && entry.lease_digest().as_bytes() == &evidence.signed_lease_digest
        && resource.resource_id() == evidence.provider_resource_id
        && resource.resource_generation() == evidence.provider_resource_generation
        && resource.resource_digest().as_bytes()
            == &evidence
                .historical_lease_signer
                .selection_floor
                .resource_digest
        && entry.resource_commitment().as_bytes() == &evidence.provider_resource_digest
        && resource.catalog_generation() == evidence.provider_catalog_generation
        && resource.catalog_digest().as_bytes() == &evidence.provider_catalog_digest
        && resource.selection_generation() == evidence.provider_selection_generation
        && resource.selection_digest().as_bytes() == &evidence.provider_selection_digest
        && entry.proof_digest().as_bytes() == &evidence.provider_proof_digest
        && proof_matches
}

fn inventory_entry_digest(entry: &SourceProviderInventoryEntryV1) -> [u8; 32] {
    let resource = entry.resource();
    let mut digest = Sha256::new();
    digest.update(entry.acquisition_id().as_bytes());
    digest.update(entry.lease_id());
    digest.update(entry.lease_digest().as_bytes());
    digest.update([entry.state() as u8, entry.proof_class()]);
    digest.update(resource.resource_namespace_digest().as_bytes());
    digest.update(resource.resource_id());
    digest.update(resource.resource_generation().to_be_bytes());
    digest.update(resource.resource_digest().as_bytes());
    digest.update(resource.catalog_generation().to_be_bytes());
    digest.update(resource.catalog_digest().as_bytes());
    digest.update(resource.selection_generation().to_be_bytes());
    digest.update(resource.selection_digest().as_bytes());
    digest.update(entry.proof_digest().as_bytes());
    digest.update(entry.resource_commitment().as_bytes());
    digest.finalize().into()
}

fn diagnostics_digest(
    domain: &[u8],
    scope: ProviderScopeV2,
    attempt_id: [u8; 32],
    values: &[DiagnosticV2],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(scope.holder_authority_id);
    digest.update(scope.provider_authority_id);
    digest.update(scope.route_id);
    digest.update(scope.resource_namespace_digest);
    digest.update(attempt_id);
    digest.update((values.len() as u32).to_be_bytes());
    for value in values {
        digest.update(value.acquisition_id);
        digest.update([value.reason]);
        digest.update(value.entry_digest);
    }
    digest.finalize().into()
}
