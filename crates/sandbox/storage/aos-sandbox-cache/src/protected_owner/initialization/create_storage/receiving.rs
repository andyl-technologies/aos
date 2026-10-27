//! Prices one active original Cache audit and its retained selection.
//!
//! Native audits are sequential only after concrete positive disposal. Every
//! failed/incomplete opener remains resident and prevents the next audit. The
//! original J high-water never refunds; these shapes create no payer or permit.

use super::*;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use crate::journal::{CacheHeldWriterShapeV1};
use crate::recovery::{
    CacheReplayRepresentationPhaseV1, general_replay_representation_bound_v1,
};
use crate::protected_owner::CacheReplayManifestGeometryV1;
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{KEY_BYTES, HEAD_BYTES};

pub use aos_sandbox_broker::controller_receiving::bank_launch::
    ControllerCacheAuditIdentityDataV1 as CacheHeldIdentityDataV1;

/// Holds actual original writer bounds and the additional sequential audit peak.
pub struct CacheCreateStorageReceivingShapeV1 {
    pub(super) identity: CacheHeldIdentityDataV1,
    pub(super) writers: [CacheHeldWriterShapeV1; 5],
    pub(super) fixed: ResourceVector,
    pub(super) additional: ResourceVector,
    pub(super) complete: ResourceVector,
}

impl CacheCreateStorageReceivingShapeV1 {
    /// Returns Eq-only DATA, never a Cache original or fresh receiving grant.
    pub fn original_identity_v1(&self) -> CacheHeldIdentityDataV1 { self.identity }

    /// Returns ADDITIONAL audit/model/append demand beyond the pure fixed bound.
    ///
    /// # Errors
    /// Actual captured constructors retain checked overflow before returning a
    /// shape. No caller can create different limits or a raw vector here.
    pub fn dominant_receiving_demand_v1(&self) -> Result<ResourceVector, CacheHeldErrorV1> {
        Ok(self.additional)
    }

    pub(super) fn complete_base(&self) -> ResourceVector { self.complete }
}

fn writer_name_demand(retained_samples: usize) -> Result<ResourceVector, CacheHeldErrorV1> {
    // Five initial + one clock-custody + one returned-HOLD sample; three
    // outer and two Native-crossing sets retain five compact positive samples
    // each. One active audit adds five. Its positive owner is really dropped
    // before the next audit, so those Vec backings are not multiplied by15.
    let mut anchors = 0_usize;
    for role in [InitializerJournal::Source, InitializerJournal::Hold,
        InitializerJournal::State, InitializerJournal::Authority, InitializerJournal::Clock]
    {
        let (root, _, _) = role.recipe();
        let width = root.components().filter(|component| matches!(component,
            std::path::Component::Normal(_))).count().checked_add(1)
            .ok_or(CacheHeldErrorV1::Order)?;
        anchors = anchors.max(width);
    }
    // A failed primary set and its owed independent outer set may each retain
    // every rooted prefix plus both named files. Successful samples dispose
    // their actual Files immediately after the complete position check.
    let files = anchors.checked_add(2).and_then(|n| n.checked_mul(2 * 5))
        .ok_or(CacheHeldErrorV1::Order)?;
    let vector_slots = anchors.checked_mul(2).and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_mul(retained_samples)).ok_or(CacheHeldErrorV1::Order)?;
    let memory = vector_slots.checked_mul(std::mem::size_of::<std::fs::File>())
        .ok_or(CacheHeldErrorV1::Order)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| CacheHeldErrorV1::Order)?)
        .with(D::OpenFiles, u64::try_from(files).map_err(|_| CacheHeldErrorV1::Order)?)
        .with(D::MetadataEntries, u64::try_from(files.checked_add(retained_samples)
            .ok_or(CacheHeldErrorV1::Order)?).map_err(|_| CacheHeldErrorV1::Order)?))
}

pub(super) fn fixed_demand() -> Result<ResourceVector, CacheHeldErrorV1> {
    let scratch = crate::DormantCacheOwnerV1::original_q04_recheck_scratch_bytes();
    let memory = std::mem::size_of::<OriginalCreateStorageCacheLoanV1<'_>>()
        .checked_add(super::append::CacheHeldAppendContextV1::receiving_construction_bytes_v1()
            .ok_or(CacheHeldErrorV1::Order)?)
        .and_then(|bytes| bytes.checked_add(
            OriginalCreateStorageCacheLoanV1::initial_audit_funding_receiving_bytes_v1()?,
        ))
        .and_then(|bytes| bytes.checked_add(scratch)).ok_or(CacheHeldErrorV1::Order)?;
    fixed_readonly_demand(memory, 5 + 1 + 1 + (3 + 2) * 5 + 5)
}

// Current uses the same fixed recipes and exact two-failure native peak. Its
// distinct bookkeeping pays only its actual new completed/active roster; no
// old terminal ordinal or previous purpose admission is reused as payment.
pub(super) fn current_fixed_demand() -> Result<ResourceVector, CacheHeldErrorV1> {
    let memory = std::mem::size_of::<(
        audit::CacheHeldAuditV1,
        ControllerCacheAuditFundingLoanV1<'_, '_>,
    )>()
        .checked_add(crate::DormantCacheOwnerV1::original_q04_recheck_scratch_bytes())
        .ok_or(CacheHeldErrorV1::Order)?;
    // Before + one active reader's complete posts + independently owed after.
    fixed_readonly_demand(memory, 3 * 5)
}

pub(super) fn fixed_readonly_demand(memory: usize, retained_samples: usize)
    -> Result<ResourceVector, CacheHeldErrorV1>
{
    let bytes = PROTECTED_CACHE_ROOT.len() + CACHE_AUTHORITY_JOURNAL.len()
        + CACHE_POLICY_HOLD_JOURNAL.len();
    let descriptors = (Path::new(PROTECTED_CACHE_ROOT).components().count() + 1) * 2;
    let cache = ReadOnlyJournalOpenOriginalsV1::fixed_preparation_demand_v1::<()>(
        u16::try_from(descriptors).map_err(|_| CacheHeldErrorV1::Order)?,
        u16::try_from(bytes).map_err(|_| CacheHeldErrorV1::Order)?,
    )?;
    let bootstrap = CacheReplayControllerBootstrapOwnerV1::create_storage_fixed_readback_demand_v1::<()>()?;
    // The actual Runtime worker stores the initializer/progress by value; its
    // compiled B worker bound already includes those inline carriers. J pays
    // additional Native path/error allocations, not that borrowed storage.
    // Exactly one active readonly owner; fifteen complete success coordinates
    // live inline in Progress. Named reopen probes coexist with that owner.
    let native = cache.componentwise_max(bootstrap);
    let names = ReadOnlyJournalOpenOriginalsV1::cache_named_receiving_demand_v1()?;
    let writer_names = writer_name_demand(retained_samples)?;
    // Two complete failed physical checks can coexist across a primary and
    // its independent post: each owns two slash/root pairs, one independent
    // flock probe and two manifest readers. Positive full checks really drop
    // all seven before reuse. Streaming reservoirs live inline in Runtime's
    // compiled worker; `scratch` covers the current construction/work peak.
    let physical = ResourceVector::ZERO.with(D::OpenFiles, 2 * (2 * 2 + 1 + 2))
        .with(D::MemoryBytes, u64::try_from(4 * (crate::physical::FIXED_CACHE_ROOT.len() + 1))
            .map_err(|_| CacheHeldErrorV1::Order)?)
        .with(D::MetadataEntries, 2 * (2 * 2 + 1 + 2));
    let additional_controls = ControllerCacheAuditFundingLoanV1::receiving_construction_bytes_v1()
        .and_then(|bytes| bytes.checked_add(
            audit::CacheHeldAuditV1::additional_control_receiving_bytes_v1()?,
        ))
        .ok_or(CacheHeldErrorV1::Order)?;
    let memory = memory.checked_add(additional_controls).ok_or(CacheHeldErrorV1::Order)?;
    let temporaries = ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| CacheHeldErrorV1::Order)?);
    Ok(native.checked_add(names)?.checked_add(writer_names)?
        .checked_add(physical)?.checked_add(temporaries)?)
}

pub(super) fn append_bytes() -> Result<u64, CacheHeldErrorV1> {
    encoded_transaction_append_bytes([
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(CACHE_HELD_RECORD_BYTES_V1) },
        RecordShape { key_bytes: KEY_BYTES, value_bytes: Some(HEAD_BYTES) },
    ].into_iter()).map_err(|_| CacheHeldErrorV1::Order)
}

pub(super) fn additional_demand(
    writers: &[CacheHeldWriterShapeV1; 5],
    authority: &Journal,
    state: &Journal,
) -> Result<ResourceVector, CacheHeldErrorV1> {
    let mut peak = ResourceVector::ZERO;
    for writer in writers {
        peak = peak.componentwise_max(writer.extent.dominant_native_receiving_demand_v1()?);
    }
    let append = append_bytes()?;
    // HOLD alone grows. Price that exact forecast before encoding or append;
    // later actual capture must equal it before the sole replay is entered.
    let hold = &writers[1];
    let forecast = hold.coordinates.end.checked_add(append).ok_or(CacheHeldErrorV1::Order)?;
    let extent = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
        hold.limits(), forecast,
    )?;
    peak = peak.componentwise_max(extent.dominant_native_receiving_demand_v1()?);
    let geometry = CacheReplayManifestGeometryV1::from_initial_journals(
        authority, state, CacheRecoveryLimitsV1::default(),
    )?;
    let models = match geometry.genesis_initial_inventory_bound()? {
        Some(value) => value,
        None => general_replay_representation_bound_v1(
            geometry.encoded_bytes(), geometry.partition_bound(),
            CacheReplayRepresentationPhaseV1::InitialInventory,
        )?,
    };
    let observations = CacheHeldSelectionV1::observation_receiving_demand_v1(authority)?;
    // The retained two-member transaction keeps its key/value Vecs. Native
    // encoding retains four complete frames plus one current record payload
    // (or the smaller commit payload); the constructor/validator keeps fixed
    // record/frame/key-set carriers. Whole-map proposals are admitted separately
    // from actual current/proposed rows before entering the append engine.
    let pair = KEY_BYTES.checked_mul(2)
        .and_then(|bytes| bytes.checked_add(CACHE_HELD_RECORD_BYTES_V1))
        .and_then(|bytes| bytes.checked_add(HEAD_BYTES)).ok_or(CacheHeldErrorV1::Order)?;
    let payload = 7_usize.checked_add(KEY_BYTES)
        .and_then(|bytes| bytes.checked_add(CACHE_HELD_RECORD_BYTES_V1)).ok_or(CacheHeldErrorV1::Order)?;
    let carriers = std::mem::size_of::<(JournalTransaction, [crate::journal::JournalRecord; 2], [Vec<u8>; 4], [usize; 2])>()
        .checked_add(KEY_BYTES * 2)
        .and_then(|bytes| bytes.checked_add(4 * std::mem::size_of::<(Vec<u8>, [usize; 6])>()))
        .ok_or(CacheHeldErrorV1::Order)?;
    let framing = u64::try_from(pair.checked_add(payload)
        .and_then(|bytes| bytes.checked_add(aos_sandbox_journal::framing::COMMIT_PAYLOAD_BYTES))
        .and_then(|bytes| bytes.checked_add(carriers)).ok_or(CacheHeldErrorV1::Order)?)
        .map_err(|_| CacheHeldErrorV1::Order)?.checked_add(append).ok_or(CacheHeldErrorV1::Order)?;
    let extra = ResourceVector::ZERO
        .with(D::MemoryBytes, framing)
        .with(D::MetadataEntries, 8)
        .with(D::StorageBytes, append).with(D::OutputBytes, append)
        .with(D::PublicationStagingBytes, append);
    Ok(peak.checked_add(models)?.checked_add(observations)?.checked_add(extra)?)
}
