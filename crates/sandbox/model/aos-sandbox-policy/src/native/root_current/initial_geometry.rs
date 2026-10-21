//! Binds the sole full RootOpen append quote to its actual native originals.
//!
//! The complete captured Authority extent and its retained upper representation
//! supplement remain separate. No key-index substitute, supplied completed
//! demand, ordinary fallback or native effect is available from this DATA code.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::kernel_clock::RetainedKernelPairedClockAttemptV1;
use aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1;
use aos_sandbox_journal::protected_storage::WriterWitnessOriginalsV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, encoded_transaction_append_bytes};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    RECORD_OVERHEAD_BYTES, root_open::ROOT_OPEN_BODY_BYTES_V1, transport::FRAME_HEADER_BYTES,
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;

use crate::native::journal::names::{
    RootFixedNameRecipeV1 as Recipe, RootFixedNameRoleV1 as Role,
    RootPolicyNameObservationOriginalV1 as Names,
};
use crate::native::PolicyNativeJournalErrorV1 as E;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_open::RootInitialClockErrorV1;
use super::preopen_geometry::ProtectedJournalPreopenReplayExtentV1;

struct HeldAppendExtentV1<'held> {
    extent: &'held ProtectedJournalPreopenReplayExtentV1,
    supplement: ResourceVector,
}

impl HeldAppendExtentV1<'_> {
    fn dominant_native_receiving_demand_v1(&self) -> Result<ResourceVector, E> {
        self.extent.dominant_native_receiving_demand_v1().map_err(E::from)
    }

    fn dominant_semantic_receiving_demand_v1(&self) -> Result<ResourceVector, E> {
        self.extent.dominant_semantic_receiving_demand_v1().map_err(E::from)?
            .checked_add(self.supplement)
            .map_err(|_| E::Mechanical(Mechanical::LimitExceeded(
                "native history observer representation",
            )))
    }
}

pub(super) fn append_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    supplement: ResourceVector,
) -> Result<ResourceVector, E> {
    let held = HeldAppendExtentV1 { extent, supplement };
    let body_bytes = ROOT_OPEN_BODY_BYTES_V1;
    let wire_bytes = FRAME_HEADER_BYTES + RECORD_OVERHEAD_BYTES + ROOT_OPEN_BODY_BYTES_V1;
    let owner_bytes = 0usize;
    aos_sandbox_protocol::fixed_root_history_append_demand_data_v1! {
        extent: held,
        body_bytes: body_bytes,
        wire_bytes: wire_bytes,
        owner_bytes: owner_bytes,
        resource_vector: ResourceVector,
        dimension: D,
        record: JournalRecord,
        record_shape: RecordShape,
        append_bytes: encoded_transaction_append_bytes,
        history: crate::q04_data::inert_root_open_history_scan_demand_v1()
            .map_err(|_| E::geometry()),
        names: names_demand_v1(10),
        clock: clock_demand_v1(),
        owed: RootCurrentHistoryPostOriginalV1::additional_resident_demand_v1()
            .map_err(|_| E::geometry()),
        error: E::Mechanical(Mechanical::LimitExceeded("fixed RootOpen append geometry")),
    }
}

// The original quote prices three identical simultaneous names groups. Each
// group retains two directory/name observations per writer and one witness per
// writer. The actual INITIAL programme reaches ten names owners: preparation2,
// crossing4 and independently owed outer4. Their own eight control identities
// are charged separately below, without claiming twelve constructed owners.
fn names_demand_v1(retained_owners: u64) -> Result<ResourceVector, E> {
    let group = names_group_demand_v1()?;
    let all = group.checked_add(group).and_then(|demand| demand.checked_add(group))
        .map_err(|_| E::geometry())?;
    let cells = Names::retained_control_cells_v1().checked_mul(retained_owners).ok_or_else(E::geometry)?;
    all.checked_add(ResourceVector::ZERO.with(D::MetadataEntries, cells)).map_err(|_| E::geometry())
}

fn names_group_demand_v1() -> Result<ResourceVector, E> {
    let mut group = ResourceVector::ZERO;
    for role in [Role::Authority, Role::Policy] {
        // The common owner supplier excludes its one embedded currentness
        // header. Restore that concrete header for the old full fixed-demand
        // law; this is a compiled native type, not a supplied scalar credit.
        let header = u64::try_from(std::mem::size_of::<WriterCurrentnessOriginalsV1<Mechanical>>())
            .map_err(|_| E::geometry())?;
        let one = Names::additional_demand_v1(role, Recipe::Location)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, header))
            .map_err(|_| E::geometry())?;
        for _ in 0..2 {
            group = group.checked_add(one).map_err(|_| E::geometry())?;
        }
    }
    let witness = WriterWitnessOriginalsV1::<Mechanical>::receiving_footprint_v1()
        .ok_or_else(E::geometry)?;
    let witnesses = witness.memory_bytes.checked_mul(2).ok_or_else(E::geometry)?;
    group = group.checked_add(ResourceVector::ZERO.with(D::MemoryBytes,
        u64::try_from(witnesses).map_err(|_| E::geometry())?))
        .map_err(|_| E::geometry())?;
    Ok(group)
}

// The fixed recipe calls this three times for the actual first, crossing and
// outer pair owners. Reached kernel files/errors remain on those same owners.
fn clock_demand_v1() -> Result<ResourceVector, E> {
    type Clock = RetainedKernelPairedClockAttemptV1<RootInitialClockErrorV1>;
    let bytes = Clock::dominant_requested_bytes_v1().ok_or_else(E::geometry)?;
    let cells = Clock::receiving_metadata_cells_v1().ok_or_else(E::geometry)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, u64::try_from(bytes).map_err(|_| E::geometry())?)
        .with(D::MetadataEntries, u64::try_from(cells).map_err(|_| E::geometry())?)
        .with(D::OpenFiles, Clock::MAXIMUM_RETAINED_FILES_V1 as u64))
}


pub(super) fn control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<Result<ResourceVector, E>>().checked_mul(3)?
        .checked_add(size_of::<u64>().checked_mul(3)?)?
        .checked_add(size_of::<(&ProtectedJournalPreopenReplayExtentV1, ResourceVector)>().checked_mul(3)?)?
        .checked_add(size_of::<HeldAppendExtentV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&HeldAppendExtentV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(18)?)?
        .checked_add(size_of::<Result<ResourceVector, Mechanical>>().checked_mul(6)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(36)?)?
        .checked_add(size_of::<([Role; 2], std::array::IntoIter<Role, 2>, Option<Role>, Role)>()
            .checked_mul(3)?)?
        .checked_add(size_of::<(std::ops::Range<i32>, Option<i32>, i32)>().checked_mul(6)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(6)?)?
        .checked_add(size_of::<Option<u64>>().checked_mul(6)?)
}


// This is Root's local append fee. The complete future Controller proposal is
// separate unsigned DATA and never supplies this actual Stage's permit.
pub(super) fn use_authorized_append_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    supplement: ResourceVector,
) -> Result<ResourceVector, E> {
    use std::mem::size_of;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::use_authorized::{
        USE_AUTHORIZED_BODY_BYTES_V1, USE_AUTHORIZED_FRAME_BYTES_V1,
    };
    let body_bytes = USE_AUTHORIZED_BODY_BYTES_V1;
    let wire_bytes = USE_AUTHORIZED_FRAME_BYTES_V1;
    let owner_bytes = size_of::<super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(size_of::<aos_sandbox_cache::CreateStorageCacheCurrentExtentsDataV1>()))
        .and_then(|bytes| bytes.checked_add(size_of::<crate::storage_create_use_data::StorageCreateUseSecurityShapeDataV1>()))
        .ok_or_else(E::geometry)?;
    continuation_append_demand_v1(extent, supplement, body_bytes, wire_bytes, owner_bytes)
}


// The same independently owed post geometry serves actual Reserved and later
// native Root turns. This supplies no arm or successful observation.
pub(super) fn history_post_demand_v1() -> Result<ResourceVector, E> {
    let names = names_group_demand_v1()?;
    let cells = Names::retained_control_cells_v1().checked_mul(4).ok_or_else(E::geometry)?;
    let names = names.checked_add(ResourceVector::ZERO.with(D::MetadataEntries, cells))
        .map_err(|_| E::geometry())?;
    let clock = clock_demand_v1()?;
    let owed = RootCurrentHistoryPostOriginalV1::additional_resident_demand_v1()
        .map_err(|_| E::geometry())?;
    names.checked_add(clock).and_then(|value| value.checked_add(owed))
        .map_err(|_| E::geometry())
}

pub(super) fn use_authorized_control_bytes_v1() -> Option<usize> {
    use std::mem::size_of;
    size_of::<(&ProtectedJournalPreopenReplayExtentV1, ResourceVector)>().checked_mul(3)?
        .checked_add(size_of::<HeldAppendExtentV1<'_>>().checked_mul(3)?)?
        .checked_add(size_of::<&HeldAppendExtentV1<'_>>().checked_mul(6)?)?
        .checked_add(size_of::<u64>().checked_mul(6)?)?
        .checked_add(size_of::<Result<ResourceVector, E>>().checked_mul(24)?)?
        .checked_add(size_of::<Result<ResourceVector, Mechanical>>().checked_mul(6)?)?
        .checked_add(size_of::<ResourceVector>().checked_mul(36)?)?
        .checked_add(size_of::<Option<usize>>().checked_mul(9)?)?
        .checked_add(size_of::<Option<u64>>().checked_mul(9)?)
}


// Each real continuation supplies its own compiled owner and actual wire widths.
// This is the same local append law, independent of prospective Controller DATA.
pub(super) fn continuation_append_demand_v1(
    extent: &ProtectedJournalPreopenReplayExtentV1,
    supplement: ResourceVector,
    body_bytes: usize,
    wire_bytes: usize,
    owner_bytes: usize,
) -> Result<ResourceVector, E> {
    let held = HeldAppendExtentV1 { extent, supplement };
    aos_sandbox_protocol::fixed_root_history_append_demand_data_v1! {
        extent: held,
        body_bytes: body_bytes,
        wire_bytes: wire_bytes,
        owner_bytes: owner_bytes,
        resource_vector: ResourceVector,
        dimension: D,
        record: JournalRecord,
        record_shape: RecordShape,
        append_bytes: encoded_transaction_append_bytes,
        history: crate::q04_data::inert_root_open_history_scan_demand_v1()
            .map_err(|_| E::geometry()),
        // Twelve inert native name owners already reside in RootOwned. Their
        // incremental control identities are paid by the incoming constructor;
        // keep all reached native name/witness backing in this local Stage.
        names: names_demand_v1(0),
        clock: clock_demand_v1(),
        owed: RootCurrentHistoryPostOriginalV1::additional_resident_demand_v1()
            .map_err(|_| E::geometry()),
        error: E::Mechanical(Mechanical::LimitExceeded("fixed RootOpen append geometry")),
    }
}
