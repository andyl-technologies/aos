//! Signed provider Inventory recovery, reconciliation, and Release currentness.
//!
//! Provider heads retain one exact signed floor plus an observation ordinal.
//! Cached conflict flags describe the projection at observation time; lifecycle
//! authority is recomputed from the current acquisition rows.

use super::*;

pub(super) fn validate_recovered_inventory_projection(
    acquisitions: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    head: &SourceProviderHeadV1,
) -> Result<()> {
    let scoped_rows = acquisitions.values().filter(|row| {
        row.provider.holder_authority_id == head.holder_authority_id
            && row.provider.provider_authority_id == head.provider_authority_id
    });
    for row in scoped_rows.clone().filter(|row| {
        row.phase == SourceAcquisitionPhaseV1::Released && row.provider_inventory_digest.is_some()
    }) {
        let proof_ordinal = row
            .provider_inventory_observation_ordinal
            .ok_or_else(|| state_error("released inventory proof lacks its observation ordinal"))?;
        let release_floor = row
            .release_inventory_observation_floor
            .ok_or_else(|| state_error("released inventory proof lacks its Release floor"))?;
        if !inventory_release_ordinals_are_ordered(
            release_floor,
            proof_ordinal,
            head.inventory_observation_ordinal,
        ) {
            return Err(state_error(
                "released inventory proof is ahead of provider observations",
            ));
        }
        if head.inventory_observation_ordinal == proof_ordinal {
            if head.inventory_digest != row.provider_inventory_digest
                || !inventory_floor_contains_terminal_release(head, row)?
            {
                return Err(state_error(
                    "released row differs from its retained inventory floor",
                ));
            }
        }
    }

    if head.inventory_observation_ordinal == 0 {
        return Ok(());
    }
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(&head.signed_inventory)
        .map_err(|error| state_error(error.to_string()))?;
    reconcile_inventory(
        acquisitions,
        head.holder_authority_id,
        head.provider_authority_id,
        signed.subject(),
    )?;
    Ok(())
}

pub(super) fn validate_recovered_inventory_result(
    head: &SourceProviderHeadV1,
    checkpoint: &ProviderDispositionCheckpointV1,
) -> Result<()> {
    if checkpoint.status != ProviderStatusV1::Complete {
        return Ok(());
    }
    if !checkpoint.signed_result.is_empty() || head.inventory_generation.is_none() {
        return Err(state_error(
            "Complete provider Inventory checkpoint differs from its floor",
        ));
    }
    let signed_request =
        SignedSourceProviderRequestV1::from_canonical_bytes(&checkpoint.signed_request)
            .map_err(|error| state_error(error.to_string()))?;
    let request = decode_inventory_request(signed_request.subject())
        .map_err(|error| state_error(error.to_string()))?;
    let signed_status =
        SignedSourceProviderStatusV1::from_canonical_bytes(&checkpoint.signed_status)
            .map_err(|error| state_error(error.to_string()))?;
    let signed_inventory =
        SignedSourceProviderInventoryV1::from_canonical_bytes(&head.signed_inventory)
            .map_err(|error| state_error(error.to_string()))?;
    let inventory = signed_inventory.subject();
    let provider = inventory.provider();
    if inventory.request_id() != request.request_id()
        || inventory.request_digest() != digest_inventory_request(&request)
        || inventory.holder_authority_id() != head.holder_authority_id
        || inventory.holder_generation() != head.holder_generation
        || inventory.holder_authority_digest().as_bytes() != &head.holder_authority_digest
        || provider.authority_id() != head.provider_authority_id
        || provider.authority_generation() != head.provider_authority_generation
        || provider.authority_digest().as_bytes() != &head.provider_authority_digest
        || provider.key_id() != head.provider_key_id
        || provider.key_generation() != head.provider_key_generation
        || provider.public_key_digest().as_bytes() != &head.provider_public_key_digest
        || signed_inventory.signer().key_id() != head.provider_key_id
        || signed_inventory.signer().authority_id() != head.provider_authority_id
        || signed_inventory.signer().authority_generation() != head.provider_authority_generation
        || signed_inventory.signer().authority_digest().as_bytes()
            != &head.provider_authority_digest
        || signed_inventory.signer().usage() != SourceProviderKeyUsageV1::ProviderReceipt
        || signed_inventory.signer().key_generation() != head.provider_key_generation
        || signed_inventory.signer().public_key_digest().as_bytes()
            != &head.provider_public_key_digest
        || signed_status.signer() != signed_inventory.signer()
        || checkpoint.result_digest
            != *response_result_digest_v1(
                SourceProviderMethod::Inventory,
                SourceProviderStatus::Complete,
                Some(&head.signed_inventory),
            )
            .as_bytes()
        || inventory.provider_process_instance()
            != signed_status.subject().provider_process_instance()
        || Some(inventory.inventory_generation()) != head.inventory_generation
        || Some(inventory.catalog_generation()) != head.catalog_generation
        || Some(*inventory.catalog_digest().as_bytes()) != head.catalog_digest
        || Some(*digest_inventory(inventory).as_bytes()) != head.inventory_digest
    {
        return Err(state_error(
            "Complete provider Inventory result differs from durable floor",
        ));
    }
    Ok(())
}

pub(super) struct InventoryReconciliationV1 {
    pub(super) has_untracked_residuals: bool,
    pub(super) has_authority_conflicts: bool,
}

/// Recomputes current authority instead of trusting observation-time diagnostics.
pub(super) fn reconcile_current_inventory(
    rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    head: &SourceProviderHeadV1,
) -> Result<Option<InventoryReconciliationV1>> {
    if head.inventory_generation.is_none() {
        return Ok(None);
    }
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(&head.signed_inventory)
        .map_err(|error| state_error(error.to_string()))?;
    Ok(Some(reconcile_inventory(
        rows,
        head.holder_authority_id,
        head.provider_authority_id,
        signed.subject(),
    )?))
}

pub(super) fn reconcile_inventory(
    rows: &BTreeMap<[u8; 32], SourceAcquisitionRowV1>,
    holder_authority_id: [u8; 16],
    provider_authority_id: [u8; 16],
    inventory: &aos_sandbox_source_provider_protocol::SourceProviderInventoryV1,
) -> Result<InventoryReconciliationV1> {
    let mut entries = BTreeMap::new();
    for entry in inventory.entries() {
        if entries
            .insert(*entry.acquisition_id().as_bytes(), entry)
            .is_some()
        {
            return Err(state_error(
                "provider inventory duplicates an acquisition ID",
            ));
        }
    }
    let mut has_untracked_residuals = entries.keys().any(|id| {
        rows.get(id).is_none_or(|row| {
            row.provider.holder_authority_id != holder_authority_id
                || row.provider.provider_authority_id != provider_authority_id
        })
    });
    let mut has_authority_conflicts = false;
    for row in rows.values().filter(|row| {
        row.provider.holder_authority_id == holder_authority_id
            && row.provider.provider_authority_id == provider_authority_id
    }) {
        let entry = entries.get(&row.acquisition_id).copied();
        if let (Some(evidence), Some(entry)) = (&row.evidence, entry) {
            if !inventory_entry_matches(evidence, entry) {
                has_authority_conflicts = true;
                continue;
            }
        } else if row.evidence.is_none() && entry.is_some() {
            has_untracked_residuals = true;
            continue;
        }
        let effective_phase = if row.phase == SourceAcquisitionPhaseV1::Faulted {
            row.faulted_from
                .unwrap_or(SourceAcquisitionPhaseV1::Faulted)
        } else {
            row.phase
        };
        match effective_phase {
            SourceAcquisitionPhaseV1::PendingQuery if row.evidence.is_none() => {}
            SourceAcquisitionPhaseV1::PendingQuery
            | SourceAcquisitionPhaseV1::DescriptorCustodied
            | SourceAcquisitionPhaseV1::Active
            | SourceAcquisitionPhaseV1::Consumed => {
                if entry.is_none_or(|entry| entry.state() != InventoryLeaseStateV1::Active) {
                    has_authority_conflicts = true;
                }
            }
            SourceAcquisitionPhaseV1::Releasing => match entry.map(|entry| entry.state()) {
                None | Some(InventoryLeaseStateV1::Released) => {}
                Some(InventoryLeaseStateV1::Reaping | InventoryLeaseStateV1::Active)
                    if row.provider_inventory_digest.is_some()
                        || row.release_generation.is_some() =>
                {
                    has_authority_conflicts = true;
                }
                Some(InventoryLeaseStateV1::Reaping) => {}
                Some(InventoryLeaseStateV1::Active) => has_authority_conflicts = true,
            },
            SourceAcquisitionPhaseV1::Released => {
                if !released_inventory_is_terminal(entry.map(|entry| entry.state())) {
                    has_authority_conflicts = true;
                }
            }
            SourceAcquisitionPhaseV1::Faulted => {
                return Err(state_error(
                    "faulted acquisition has an invalid source phase",
                ));
            }
        }
    }
    Ok(InventoryReconciliationV1 {
        has_untracked_residuals,
        has_authority_conflicts,
    })
}

pub(super) fn inventory_floor_proves_terminal_release(
    head: &SourceProviderHeadV1,
    row: &SourceAcquisitionRowV1,
) -> Result<bool> {
    let Some(observation_floor) = row.release_inventory_observation_floor else {
        return Ok(false);
    };
    if !inventory_observation_postdates_release(head, observation_floor) {
        return Ok(false);
    }
    inventory_floor_contains_terminal_release(head, row)
}

pub(super) const fn inventory_observation_postdates_release(
    head: &SourceProviderHeadV1,
    observation_floor: u64,
) -> bool {
    head.inventory_observation_ordinal > observation_floor
}

pub(super) const fn inventory_release_ordinals_are_ordered(
    release_floor: u64,
    proof_ordinal: u64,
    current_ordinal: u64,
) -> bool {
    proof_ordinal > release_floor && proof_ordinal <= current_ordinal
}

fn inventory_floor_contains_terminal_release(
    head: &SourceProviderHeadV1,
    row: &SourceAcquisitionRowV1,
) -> Result<bool> {
    let signed = SignedSourceProviderInventoryV1::from_canonical_bytes(&head.signed_inventory)
        .map_err(|error| state_error(error.to_string()))?;
    let entry = signed
        .subject()
        .entries()
        .iter()
        .find(|entry| entry.acquisition_id().as_bytes() == &row.acquisition_id);
    match entry {
        None => Ok(true),
        Some(entry) => Ok(entry.state() == InventoryLeaseStateV1::Released
            && row
                .evidence
                .as_ref()
                .is_some_and(|evidence| inventory_entry_matches(evidence, entry))),
    }
}

pub(super) const fn released_inventory_is_terminal(entry: Option<InventoryLeaseStateV1>) -> bool {
    matches!(entry, None | Some(InventoryLeaseStateV1::Released))
}

fn inventory_entry_matches(
    evidence: &SourceAcquisitionEvidenceV1,
    entry: &aos_sandbox_source_provider_protocol::SourceProviderInventoryEntryV1,
) -> bool {
    let expected_class = match evidence.proof_class {
        SourceAcquisitionProofClassV1::ImmutableTree => matches!(entry.proof_class(), 1 | 3),
        SourceAcquisitionProofClassV1::LocalLive => entry.proof_class() == 2,
        SourceAcquisitionProofClassV1::BestEffortReplica => entry.proof_class() == 4,
    };
    entry.lease_id() == evidence.lease_id
        && entry.lease_digest().as_bytes() == &evidence.signed_lease_digest
        && entry.resource().resource_id() == evidence.provider_resource_id
        && entry.resource().resource_generation() == evidence.provider_resource_generation
        && entry.resource_commitment().as_bytes() == &evidence.provider_resource_digest
        && entry.resource().catalog_generation() == evidence.provider_catalog_generation
        && entry.resource().catalog_digest().as_bytes() == &evidence.provider_catalog_digest
        && entry.resource().selection_generation() == evidence.provider_selection_generation
        && entry.resource().selection_digest().as_bytes() == &evidence.provider_selection_digest
        && entry.proof_digest().as_bytes() == &evidence.provider_proof_digest
        && expected_class
}
