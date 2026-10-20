//! Supplies fixed local bootstrap and actual historical model demand DATA.
//!
//! Only the genuine Ownership receiving loan may spend its original F. These
//! recipes accept no replacement vector, financial account, role or callback.
//! The native captured-Journal engine separately prices its physical/parser
//! prefix and materialized map before handing the actual Journal here.

use std::mem::size_of;

use aos_sandbox_core::model::{KeyReference, TrustPolicy};
use aos_sandbox_core::{FeatureRef, ResourceDimension as D, ResourceVector};
use crate::OwnershipHistoryBounds;

use super::*;

pub(crate) fn fixed_startup_demand_v1() -> Option<ResourceVector> {
    let policy = 64usize.checked_mul(1024)?;
    // The bootstrap reader's original buffer, raw policy extraction, anchor
    // canonical bytes and one independently decoded verification-policy peak
    // coexist. Hostile policy cells cannot outnumber their encoded bytes.
    let buffers = MAXIMUM_BOOTSTRAP_BYTES.checked_add(policy.checked_mul(3)?)?;
    let policy_cells = policy.checked_mul(size_of::<KeyReference>()
        .checked_add(size_of::<FeatureRef>())?)?;
    let directory = std::path::Path::new("/run/credentials/aos-sandbox-ownershipd.service");
    let joined_paths = aos_sandbox_linux::credential::FixedRoleCredentialReadV1::
        joined_path_receiving_bytes_v1(directory, "ownership-signing-key")?
        .max(aos_sandbox_linux::credential::FixedRoleCredentialReadV1::
            joined_path_receiving_bytes_v1(directory, "node-id")?);
    let requested = buffers.checked_add(policy_cells)?
        .checked_add(joined_paths)?
        .checked_add(size_of::<TrustPolicy>())?
        .checked_add(32 + 16)?
        .checked_add(aos_sandbox_broker::paired_clock::PairedClockSamplesV1::representation_memory_bytes())?
        .checked_add(size_of::<ProtectedLocalBootstrapFailureV1>())?
        .checked_add(size_of::<ProtectedLocalSigningFailureV1>())?
        .checked_add(size_of::<ProtectedLocalOwnershipStartupFailureV1>())?;
    // The retained directory/bootstrap/two credentials and five boot readers
    // contribute nine named entries. Hostile decoded policy key/feature cells
    // cannot outnumber their separately admitted canonical policy bytes.
    let metadata = policy.checked_mul(2)?.checked_add(9)?;
    // Dir+bootstrap+two credentials, original boot and four signing bookends.
    // A receiving original may cover this FD geometry only through its actual
    // same-flight permanent coverage proof; this DATA does not suppress it.
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(requested).ok()?)
        .with(D::OpenFiles, 9)
        .with(D::MetadataEntries, u64::try_from(metadata).ok()?))
}

pub(crate) fn history_capture_demand_v1(
    journal: &crate::Journal,
) -> Result<ResourceVector, DurableOwnershipAuthorityError> {
    journal.ensure_healthy()?;
    let failed = || DurableOwnershipAuthorityError::ResourceExhausted;
    let (entries, bytes) = journal.records(aos_sandbox_core::RecordNamespace::Operation).try_fold(
        (0usize, 0usize), |(count, bytes), (key, value)| {
            if key.len() > OwnershipHistoryBounds::MAXIMUM_KEY_BYTES
                || value.len() > OwnershipHistoryBounds::MAXIMUM_ENTRY_BYTES
            {
                return Err(failed());
            }
            Ok((count.checked_add(1).ok_or_else(failed)?,
                bytes.checked_add(value.len()).ok_or_else(failed)?))
        },
    )?;
    let currents = journal.records(aos_sandbox_core::RecordNamespace::DesiredState).count();
    if journal.records(aos_sandbox_core::RecordNamespace::Effect).next().is_some()
        || journal.records(aos_sandbox_core::RecordNamespace::Idempotency).next().is_some()
    {
        return Err(DurableOwnershipAuthorityError::CorruptState);
    }
    let memory = OwnershipHistoryBounds::replay_requested_memory_bytes_v1(entries, bytes, currents)
        .ok_or_else(failed)?;
    let metadata = entries.checked_mul(6).and_then(|rows| rows.checked_add(currents.checked_mul(2)?))
        .ok_or_else(failed)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| failed())?)
        .with(D::MetadataEntries, u64::try_from(metadata).map_err(|_| failed())?))
}

/// Prices one permanently retained signed-completion map node and its artifacts.
pub(crate) fn retained_signing_demand_v1() -> Option<ResourceVector> {
    let response = aos_sandbox_ownership_protocol::protocol::MAXIMUM_OWNERSHIP_RESPONSE_BYTES as usize;
    // One full B-tree node per logical entry dominates its amortized node share.
    let cell = size_of::<[u8; 16]>().checked_add(size_of::<LocalOwnershipSigningAttemptV1>())?;
    let bytes = cell.checked_mul(11)?.checked_add(16 * size_of::<usize>())?
        .checked_add(std::mem::align_of::<[u8; 16]>())?
        .checked_add(std::mem::align_of::<LocalOwnershipSigningAttemptV1>())?
        .checked_add(response.checked_mul(4)?)?;
    Some(ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?)
        .with(D::MetadataEntries, 1))
}

/// Prices the bounded transient canonical model/encoder/signature peak.
/// Native replay and lasting signing/append nodes have their own actual joins.
pub(crate) fn fixed_request_demand_v1() -> Option<ResourceVector> {
    let response = aos_sandbox_ownership_protocol::protocol::MAXIMUM_OWNERSHIP_RESPONSE_BYTES as usize;
    let request = aos_sandbox_ownership_protocol::protocol::MAXIMUM_OWNERSHIP_REQUEST_BYTES as usize;
    let bytes = response.checked_mul(8)?.checked_add(request.checked_mul(4)?)?
        .checked_add(size_of::<LocalOwnershipProtocolAttemptV1>())?
        .checked_add(size_of::<crate::JournalTransaction>())?;
    let mut request = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(bytes).ok()?);
    // Complete has one query audit, one signing audit, and four append
    // observations (before/prehistory/history/post). Their real names stay
    // held together until publication; only that exact positive flow disposes.
    let names = crate::journal::OwnershipCapturedJournalOpenV1::named_currentness_demand_v1().ok()?;
    for _ in 0..6 { request = request.checked_add(names).ok()?; }
    Some(request)
}

/// Supplies consumed IPC/result byte bounds for one canonical request.
/// The service reserves this on the same original before receive/encoding;
/// positive disposal never subtracts these dimensions from its ledger.
pub(crate) fn request_io_demand_v1() -> Option<ResourceVector> {
    let request = u64::from(aos_sandbox_ownership_protocol::protocol::MAXIMUM_OWNERSHIP_REQUEST_BYTES);
    let response = u64::from(aos_sandbox_ownership_protocol::protocol::MAXIMUM_OWNERSHIP_RESPONSE_BYTES);
    Some(ResourceVector::ZERO.with(D::NetworkBytes, request.checked_add(response)?)
        .with(D::OutputBytes, response))
}

/// Prices the same complete two-sample clock owner's dynamic backing.
pub(crate) fn retained_paired_clock_demand_v1() -> Option<ResourceVector> {
    aos_sandbox_broker::paired_clock::PairedClockSamplesV1::receiving_demand_v1()
}
