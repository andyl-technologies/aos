//! Folds the complete validated Cache history into actionable lifecycle rows.
//!
//! Ordinary Boot and the retained Delete consumer share this pure selection.
//! The containing protected projection commits all rows, including accounting
//! and inactive history. These selected rows create neither native currentness
//! nor Cache/Root/financial authority.

use super::*;

pub(super) fn actionable_rows_v1(
    inventories: Vec<CacheRecoveryInventoryV1>,
) -> Result<Vec<crate::lifecycle::LifecycleBootDomainEntryV1>, CacheResidencyProtectedJournalErrorV1> {
    actionable_rows_data_v2(inventories.into_iter().map(CacheRecoveryInventoryV1::into_parsed_history_data_v1))
}

// Historical DATA remains distinct from the Native opaque inventories above.
// Both actual consumers use this sole selection/sort/cardinality engine.
pub(crate) fn actionable_rows_data_v2<I>(inventories: impl IntoIterator<Item = I>)
    -> Result<Vec<crate::lifecycle::LifecycleBootDomainEntryV1>, CacheResidencyProtectedJournalErrorV1>
where I: std::borrow::Borrow<aos_sandbox_protocol::cache_state::recovery::CacheRecoveryInventoryDataV1> {
    let mut entries = Vec::new();
    for inventory in inventories {
        let inventory: &aos_sandbox_protocol::cache_state::recovery::CacheRecoveryInventoryDataV1 = inventory.borrow();
        for payload in &inventory.reconstructed {
            if matches!(
                payload.reservation.state,
                ReservationStateV1::Reserved | ReservationStateV1::Uncertain
            ) {
                entries.push(
                    crate::lifecycle::LifecycleBootDomainEntryV1::from_protected_cache(
                        LifecycleResourceV1::Capability(
                            aos_sandbox_model::ResourceId::from_bytes(
                                *payload.reservation.id.as_bytes(),
                            ),
                        ),
                        payload.reservation.digest,
                    )
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                );
            }

            if let Some(catalog) = payload
                .catalog
                .as_ref()
                .filter(|catalog| catalog.presence != CatalogPresenceV1::Evicted)
            {
                let mut environment = [0_u8; 16];
                environment.copy_from_slice(&catalog.descriptor.digest().as_bytes()[..16]);
                entries.push(
                    crate::lifecycle::LifecycleBootDomainEntryV1::from_protected_cache(
                        LifecycleResourceV1::Environment(
                            aos_sandbox_model::ResourceId::from_bytes(environment),
                        ),
                        catalog.digest,
                    )
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                );
            }

            for pin in &payload.pins {
                let resource = if let Some(attachment) = pin.attachment {
                    LifecycleResourceV1::Attachment(
                        aos_sandbox_model::ResourceId::from_bytes(*attachment.as_bytes()),
                    )
                } else {
                    LifecycleResourceV1::View(pin.view)
                };
                // Physical obligations remain distinct across disclosure partitions.
                let identity = ObjectDigest::from_bytes(
                    Sha256::new()
                        .chain_update(b"aos.sandbox.lifecycle.cache-pin-physical-row.v2\0")
                        .chain_update(pin.partition.digest().as_bytes())
                        .chain_update(pin.id.as_bytes())
                        .chain_update(pin.object.digest().as_bytes())
                        .chain_update([pin.kind as u8])
                        .finalize()
                        .into(),
                );
                entries.push(
                    crate::lifecycle::LifecycleBootDomainEntryV1::from_protected_cache(
                        resource, identity,
                    )
                    .map_err(|_| ProtectedDomainJournalErrorV1::NonCanonicalRecord)?,
                );
            }
        }
    }
    entries.sort_unstable();
    entries.dedup();
    if entries.len() > crate::lifecycle::MAXIMUM_LIFECYCLE_EXPECTATIONS {
        return Err(ProtectedDomainJournalErrorV1::NonCanonicalRecord);
    }
    Ok(entries)
}

// Bounds the selected Vec from actual reconstructed payload/pin cardinalities.
// Both potential reservation/catalog rows are conservatively retained; the
// sole selector below decides which actual semantic rows survive.
pub(crate) fn actionable_rows_receiving_demand_v2<'data>(
    inventories: impl IntoIterator<Item = &'data aos_sandbox_protocol::cache_state::recovery::CacheRecoveryInventoryDataV1>,
) -> Option<aos_sandbox_model::ResourceVector> {
    let mut rows = 0usize;
    for inventory in inventories {
        rows = rows.checked_add(inventory.reconstructed.len().checked_mul(2)?)?;
        for payload in &inventory.reconstructed { rows = rows.checked_add(payload.pins.len())?; }
    }
    let bytes = rows.checked_mul(std::mem::size_of::<crate::lifecycle::LifecycleBootDomainEntryV1>())?
        .checked_mul(3)?.checked_add(3 * std::mem::size_of::<Vec<crate::lifecycle::LifecycleBootDomainEntryV1>>())?
        .checked_add(3 * std::mem::size_of::<sha2::Sha256>())?;
    Some(aos_sandbox_model::ResourceVector::ZERO.with(aos_sandbox_model::ResourceDimension::MemoryBytes,
        u64::try_from(bytes).ok()?))
}
