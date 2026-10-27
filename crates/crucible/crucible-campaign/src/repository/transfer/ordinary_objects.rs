//! Ordinary archive-object copy with compatibility and supervised paths.
//!
//! The compatibility path preserves the original local API. Journaled and
//! explicitly bounded callers use checked readers and the checked publication
//! transaction so cancellation cannot skip private-staging cleanup.

use std::io;

use super::*;

/// Selects the ordinary object's publication and supervision contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// Preserves the local API's caller-held publication fences.
    Compatibility,
    /// Uses the original operation's checked readers and private staging.
    Checked,
}

/// Copies and authenticates one ordinary archive object.
///
/// # Errors
///
/// Returns missing checked authority, cancellation, corrupt contents or receipts,
/// insufficient durability, or a storage failure with its cleanup outcome.
#[allow(clippy::too_many_arguments)]
pub(super) fn transfer(
    source: &CampaignRepository,
    destination: &CampaignRepository,
    id: ContentId,
    logical_length: u64,
    durability: DurabilityRequirement,
    source_original: Option<&crucible_store::owned_decode::DecodeBudget>,
    destination_original: Option<&crucible_store::owned_decode::DecodeBudget>,
    boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    mode: Mode,
    report: &mut CampaignArchiveTransferReport,
) -> Result<(), CampaignRepositoryError> {
    match mode {
        Mode::Compatibility => {
            compatibility(source, destination, id, logical_length, durability, report)
        }
        Mode::Checked => checked(
            source,
            destination,
            id,
            logical_length,
            durability,
            source_original.ok_or(StoreError::Unsupported {
                capability: "campaign-archive-source-object-admission",
            })?,
            destination_original.ok_or(StoreError::Unsupported {
                capability: "campaign-archive-destination-object-admission",
            })?,
            boundary,
            report,
        ),
    }
}

fn compatibility(
    source: &CampaignRepository,
    destination: &CampaignRepository,
    id: ContentId,
    logical_length: u64,
    durability: DurabilityRequirement,
    report: &mut CampaignArchiveTransferReport,
) -> Result<(), CampaignRepositoryError> {
    let existed = match destination.blobs.read(id, None) {
        Ok(existing) => {
            if existing.logical_length() != logical_length {
                return Err(StoreError::Corrupt { id }.into());
            }
            existing.copy_to(&mut io::sink())?;
            true
        }
        Err(StoreError::NotFound { .. }) => false,
        Err(source) => return Err(source.into()),
    };

    let source_handle = source.blobs.read(id, None)?;
    if source_handle.logical_length() != logical_length {
        return Err(StoreError::Corrupt { id }.into());
    }
    let receipt = destination.blobs.put_if_absent(id, &source_handle)?;
    accept_compatibility_receipt(id, logical_length, durability, &receipt)?;
    let observed_durable_placements = receipt.durable_placements();
    let persisted = destination.blobs.read(id, None)?;
    if persisted.logical_length() != logical_length {
        return Err(StoreError::Corrupt { id }.into());
    }
    persisted.copy_to(&mut io::sink())?;
    update_report(report, existed, logical_length, observed_durable_placements)
}

#[allow(clippy::too_many_arguments)]
fn checked(
    source: &CampaignRepository,
    destination: &CampaignRepository,
    id: ContentId,
    logical_length: u64,
    durability: DurabilityRequirement,
    source_original: &crucible_store::owned_decode::DecodeBudget,
    destination_original: &crucible_store::owned_decode::DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), crucible_store::ram::RamStoreError>,
    report: &mut CampaignArchiveTransferReport,
) -> Result<(), CampaignRepositoryError> {
    let (existed, observed_durable_placements) =
        crucible_store::ram::with_store_operation_boundary(
            destination_original,
            boundary,
            |checked_boundary| {
                let existed = match destination.blobs.read_with_boundary(
                    destination_original,
                    id,
                    None,
                    checked_boundary,
                ) {
                    Ok(existing) => {
                        if existing.logical_length() != logical_length {
                            return Err(StoreError::Corrupt { id });
                        }
                        existing.authenticate_with_boundary(
                            destination_original,
                            id,
                            checked_boundary,
                        )?;
                        true
                    }
                    Err(StoreError::NotFound { .. }) => false,
                    Err(source) => return Err(source),
                };

                let source_handle =
                    source
                        .blobs
                        .read_with_boundary(source_original, id, None, checked_boundary)?;
                if source_handle.logical_length() != logical_length {
                    return Err(StoreError::Corrupt { id });
                }
                let objects = [(id, source_handle)];
                let receipts = destination.blobs.put_many_if_absent_with_boundary(
                    destination_original,
                    &objects,
                    checked_boundary,
                )?;
                let [receipt] = &*receipts else {
                    return Err(StoreError::InvalidComposition {
                        reason: "single-object transfer returned a non-singleton receipt",
                    });
                };
                accept_receipt_store(id, logical_length, durability, receipt)?;
                let observed_durable_placements = receipt.durable_placements();
                let receipts = receipts.accept_with_boundary(checked_boundary)?;

                let persisted = destination.blobs.read_with_boundary(
                    destination_original,
                    id,
                    None,
                    checked_boundary,
                )?;
                if persisted.logical_length() != logical_length {
                    return Err(StoreError::Corrupt { id });
                }
                persisted.authenticate_with_boundary(destination_original, id, checked_boundary)?;
                // This final poll separates complete EOF authentication from
                // the caller-visible receipt and report transition.
                checked_boundary()?;
                drop(receipts);
                Ok((existed, observed_durable_placements))
            },
        )
        .map_err(|source| match source {
            crucible_store::ram::RamStoreError::Store(source) => {
                CampaignRepositoryError::Store(source)
            }
            source => CampaignRepositoryError::Ram(source),
        })?;

    update_report(report, existed, logical_length, observed_durable_placements)
}

fn accept_compatibility_receipt(
    id: ContentId,
    logical_length: u64,
    durability: DurabilityRequirement,
    receipt: &crucible_store::content_store::PutReceipt,
) -> Result<(), CampaignRepositoryError> {
    if receipt.id != id
        || receipt
            .placements
            .iter()
            .any(|placement| placement.logical_length != logical_length)
    {
        return Err(StoreError::Corrupt { id }.into());
    }
    let observed_durable_placements = receipt.durable_placements();
    if observed_durable_placements < usize::from(durability.minimum_durable_placements()) {
        let observed_durable_placements = u16::try_from(observed_durable_placements)
            .map_err(|_| integrity("campaign-archive-durable-placement-count-overflow"))?;
        return Err(StoreError::DurabilityUnsatisfied {
            id,
            minimum_durable_placements: durability.minimum_durable_placements(),
            observed_durable_placements,
        }
        .into());
    }
    Ok(())
}

fn accept_receipt_store(
    id: ContentId,
    logical_length: u64,
    durability: DurabilityRequirement,
    receipt: &crucible_store::content_store::PutReceipt,
) -> Result<(), StoreError> {
    let observed_durable_placements = receipt.durable_placements();
    if receipt.id != id
        || receipt
            .placements
            .iter()
            .any(|placement| placement.logical_length != logical_length)
    {
        return Err(StoreError::Corrupt { id });
    }
    if observed_durable_placements < usize::from(durability.minimum_durable_placements()) {
        let observed_durable_placements =
            u16::try_from(observed_durable_placements).map_err(|_| StoreError::Quota)?;
        return Err(StoreError::DurabilityUnsatisfied {
            id,
            minimum_durable_placements: durability.minimum_durable_placements(),
            observed_durable_placements,
        });
    }
    Ok(())
}

fn update_report(
    report: &mut CampaignArchiveTransferReport,
    existed: bool,
    logical_length: u64,
    observed_durable_placements: usize,
) -> Result<(), CampaignRepositoryError> {
    report.observe_durable_placements(observed_durable_placements)?;
    if existed {
        report.existing_objects = report
            .existing_objects
            .checked_add(1)
            .ok_or_else(|| integrity("campaign-archive-transfer-count-overflow"))?;
    } else {
        report.copied_objects = report
            .copied_objects
            .checked_add(1)
            .ok_or_else(|| integrity("campaign-archive-transfer-count-overflow"))?;
        report.copied_bytes = report
            .copied_bytes
            .checked_add(logical_length)
            .ok_or_else(|| integrity("campaign-archive-transfer-byte-overflow"))?;
    }
    Ok(())
}
