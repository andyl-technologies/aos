//! Quotes a complete new Producer lifecycle from the latest verified checkpoint.
//!
//! The same Source fence supplies typed/raw pairs and a genuine pending scheduler
//! grant. These values are DATA: every native original separately spends ingress
//! and action axes of the original startup window before receiving or mutating.
//! Prior successful, failed and uncertain histories remain charged independently.

use super::*;
use crate::bodies::BeginKind;
use crate::reference_packet::control::PacketNativeRecord;
use crate::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerOperationData;
use crate::reference_packet::service::{
    PacketNative5SourceLaunch, complete_restore::PacketNativeRestoredRecord,
};
use crate::reference_packet::{PacketEvent, PacketGrant, PacketInventory, PacketPublication};
use crate::retained_metadata::serialization_storage::OriginalSerializationStorageData;
use crucible_node_format::{Id, Position};
use std::mem::size_of;

#[path = "producer_lifecycle/projection.rs"]
pub(super) mod projection;

/// Borrows actual current Source owners; none of these values issues a grant.
pub struct PacketRestoredProducerLifecycleInputs<'a> {
    /// Borrows the same original startup carrier, whose axes are never widened.
    pub startup: &'a PacketNativeRestoredSuffixStartupStorageData,
    /// Borrows the actual installed typed launch.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows its complete retained canonical launch5 bank.
    pub canonical_launch5: &'a [u8],
    /// Borrows the latest fully verified post-retirement restored12 checkpoint.
    pub checkpoint: &'a PacketNativeRestoredRecord,
    /// Borrows its full retained canonical restored12 bank.
    pub canonical_checkpoint: &'a [u8],
    /// Borrows the complete underlying current grant-free Producer2 record.
    pub producer: &'a PacketNativeRecord,
    /// Borrows its full retained canonical Producer2 bank.
    pub canonical_producer: &'a [u8],
    /// Borrows the genuine pending operation coordinates independently of the wire.
    pub operation: PacketRestoredProducerOperationData<'a>,
    /// Borrows target identity and the genuine common-grant projection's byte ceiling.
    pub arguments: PacketRestoredProducerArgumentsData<'a>,
}

/// Borrows argument geometry without constructing a future typed or JSON owner.
///
/// The Source binds the held target and this byte ceiling to the defining
/// common-grant projection under its actual operation/Window claim. A number
/// cannot grant authority. After admission, the same caller checks the actual
/// encoded authorization and arguments before assigning any SDK original.
#[derive(Clone, Copy)]
pub struct PacketRestoredProducerArgumentsData<'a> {
    /// Borrows the actual immutable Commit target from this Source association.
    pub held:
        &'a crate::reference_packet::service::complete_restore::PacketNativeRestoredCommitHold,
    /// Bounds the genuine separately projected common authorization object.
    pub maximum_authorization_bytes: usize,
}

/// Describes the actual prospective model population without owning model bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketRestoredProducerPopulationData {
    pending_before: usize,
    pending_after: usize,
    completed: usize,
    newborn: usize,
    payload_bytes: usize,
    event_id_bytes: usize,
    operation_id_bytes: usize,
}

impl PacketRestoredProducerPopulationData {
    /// Returns callbacks still pending before this exact operation.
    pub const fn pending_before_data(&self) -> usize {
        self.pending_before
    }
    /// Returns callbacks remaining after this exact complete prefix.
    pub const fn pending_after_data(&self) -> usize {
        self.pending_after
    }
    /// Returns callbacks wholly inside the exclusive operation ceiling.
    pub const fn completed_callbacks_data(&self) -> usize {
        self.completed
    }
    /// Returns genuine prospective output publications, independently of fanout.
    pub const fn newborn_publications_data(&self) -> usize {
        self.newborn
    }
    /// Returns complete prospective newborn payload extent.
    pub const fn newborn_payload_bytes_data(&self) -> usize {
        self.payload_bytes
    }
    /// Returns complete prospective newborn event identifier extent.
    pub const fn newborn_event_id_bytes_data(&self) -> usize {
        self.event_id_bytes
    }
    /// Returns this genuine operation identifier extent for each output owner.
    pub const fn operation_id_bytes_data(&self) -> usize {
        self.operation_id_bytes
    }
}

/// Retains fixed independent demands and exact same-checkpoint quote identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PacketRestoredProducerLifecycleStorageData {
    startup: PacketNativeRestoredSuffixStartupStorageData,
    identity: [u8; 32],
    population: PacketRestoredProducerPopulationData,
    ingress: PacketNativeStartupAllocationRow,
    action: PacketNativeStartupAllocationRow,
    host_retained: usize,
    host_transient: usize,
    source_retained: usize,
    source_transient: usize,
    maximum_report: usize,
    originals: usize,
    scratch: usize,
    requested: usize,
}

impl PacketRestoredProducerLifecycleStorageData {
    /// Returns an independent per-original native ingress demand, never authority.
    pub const fn native_ingress_data(&self) -> PacketNativeStartupAllocationRow {
        self.ingress
    }
    /// Returns the independently spent current-model native action demand.
    pub const fn native_action_data(&self) -> PacketNativeStartupAllocationRow {
        self.action
    }
    /// Returns all new retained SDK attempts, uploads, terminal and ACK owners.
    pub const fn host_retained_requested_bytes_data(&self) -> usize {
        self.host_retained
    }
    /// Returns simultaneous new SDK assignment, decoding, upload and ACK work.
    pub const fn host_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.host_transient
    }
    /// Returns fixed quote and SDK partial/result views.
    pub const fn host_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
    /// Returns independent Source raw, typed, Value and canonical report owners.
    pub const fn source_evidence_retained_requested_bytes_data(&self) -> usize {
        self.source_retained
    }
    /// Returns simultaneous full Source proof/report parsing and validation work.
    pub const fn source_evidence_maximum_simultaneous_transient_bytes_data(&self) -> usize {
        self.source_transient
    }
    /// Returns Source borrowed proof, report and defining quote views.
    pub const fn source_evidence_counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }
    /// Bounds the exact defining report serializer, including every full envelope.
    pub const fn maximum_report_encoded_bytes_data(&self) -> usize {
        self.maximum_report
    }
    /// Returns the unchanged closed restored12 canonical evidence ceiling.
    pub const fn maximum_restored_record_bytes_data(&self) -> usize {
        65_536
    }
    /// Returns the independently enforced complete underlying Producer2 ceiling.
    pub const fn maximum_underlying_record_bytes_data(&self) -> usize {
        65_536
    }
    /// Returns every Begin/Poll/Retire/Observe and authorization/consumption upload original.
    pub const fn maximum_originals_data(&self) -> usize {
        self.originals
    }
    /// Bounds each actual raw upload chunk under the same sealed frame grammar.
    ///
    /// # Errors
    /// Refuses a sealed frame too short for a complete closed upload envelope.
    pub fn maximum_upload_chunk_bytes_data(&self) -> Result<usize, ProviderError> {
        projection::chunk_bytes(self.startup.frame_bytes_data())
    }
    /// Copies prospective actual model populations for independently priced common DTOs.
    pub const fn population_data(&self) -> PacketRestoredProducerPopulationData {
        self.population
    }
    /// Returns all new independent host, Source and native demands together.
    pub const fn requested_bytes_data(&self) -> usize {
        self.requested
    }
    /// Compares every same-checkpoint identity, population, bound and byte axis.
    ///
    /// # Errors
    /// Refuses another operation, checkpoint, startup carrier or produced demand.
    pub fn authenticate_same_quote_data(&self, other: &Self) -> Result<(), ProviderError> {
        if self != other {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Projects a complete new no-input Producer lifecycle before its first effect.
///
/// The Source authenticates every borrowed typed/raw pair and current member
/// before and after this call. The original native reservation is not replaced:
/// each real original later independently debits the returned actual method row.
/// This quote retains all new lifecycle owners at once, even when their calls are
/// sequential. It supplies no discount for earlier durable publication or ACK.
///
/// # Errors
/// Refuses another program, partial/current grant, noncontiguous operation,
/// invalid finite raw extent, malformed startup correspondence, checked overflow
/// or any complete additive demand above `maximum`.
pub fn original_restored_producer_lifecycle_storage_data(
    input: &PacketRestoredProducerLifecycleInputs<'_>,
    maximum: usize,
) -> Result<PacketRestoredProducerLifecycleStorageData, ProviderError> {
    input
        .startup
        .authenticate_observation_quote_inputs_data(input.launch, input.canonical_launch5)?;
    crate::reference_packet::service::complete_restore::producer_progress::original_restored_producer_report_storage_data(input.launch, maximum)?;
    let population = projection::population(input)?;
    let frame = input.startup.frame_bytes_data();
    let projected = projection::project(input, maximum)?;
    let scratch = original_restored_producer_lifecycle_counter_scratch_data();
    let ingress = super::producer_ingress::original_restored_producer_ingress_row_data(frame)?;
    let model = projection::typed_model_backing(input)?;
    let malformed_proof =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            65_536,
        )?;
    let action =
        native_closed_producer_action_row_data(input.launch, projected.upload_bytes, maximum)?;
    let originals = projection::originals(input, frame)?;
    let wire = projected.wire.requested_total()?;
    let host_retained = sum(&[
        mul(
            originals,
            sum(&[
                mul(wire, 8)?,
                usize::try_from(ingress.requested_peak_data()?).map_err(|_| invalid())?,
                size_of::<crate::client::OriginalRestoredSuffixHostAttempt>(),
            ])?,
        )?,
        mul(projected.proof.requested_total()?, 8)?,
        projected.upload_bytes,
    ])?;
    let host_transient = sum(&[
        mul(wire, 8)?,
        mul(projected.proof.requested_total()?, 4)?,
        projected.upload_bytes,
    ])?;
    let source_retained = sum(&[mul(model, 4)?, mul(projected.proof.requested_total()?, 8)?,
        mul(4, malformed_proof.value_dom_requested_bytes)?,
        projected.report.retained_value_backing_bytes, projected.report.canonical_output_requested_bytes,
        size_of::<crate::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerOperationReportData<'static>>()])?;
    let malformed_model_arrays = mul(
        malformed_proof.maximum_value_nodes,
        mul(
            4,
            sum(&[size_of::<PacketEvent>(), size_of::<PacketPublication>()])?,
        )?,
    )?;
    let source_transient = sum(&[
        mul(model, 4)?,
        mul(projected.proof.requested_total()?, 8)?,
        mul(4, malformed_proof.canonical_pass_requested_bytes()?)?,
        malformed_model_arrays,
        projected.report.requested_total()?,
    ])?;
    let requested = sum(&[
        host_retained,
        host_transient,
        source_retained,
        source_transient,
        mul(scratch, 2)?,
        mul(
            originals,
            usize::try_from(ingress.requested_peak_data()?).map_err(|_| invalid())?,
        )?,
        mul(
            originals,
            usize::try_from(action.retained_requested_bytes.get()).map_err(|_| invalid())?,
        )?,
        usize::try_from(action.maximum_simultaneous_transient_bytes.get())
            .map_err(|_| invalid())?,
        usize::try_from(action.declared_counter_scratch_bytes.get()).map_err(|_| invalid())?,
    ])?;
    if requested > maximum {
        return Err(ProviderError::ResourceExhausted(
            "restored Producer whole lifecycle construction",
        ));
    }
    Ok(PacketRestoredProducerLifecycleStorageData {
        startup: *input.startup,
        identity: projection::identity(input),
        population,
        ingress,
        action,
        host_retained,
        host_transient,
        source_retained,
        source_transient,
        maximum_report: projected.report.maximum_encoded_bytes,
        originals,
        scratch,
        requested,
    })
}

/// Recounts the same closed native action geometry independently of current credit.
///
/// The owning native caller first validates its actual Producer model/operation
/// and passes the actual upload extent. This function issues no native scope.
/// Every returned axis must fit the original reservation's remaining axes.
pub(crate) fn native_closed_producer_action_row_data(
    launch: &PacketNative5SourceLaunch,
    upload_bytes: usize,
    maximum: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    use crate::reference_packet::service::complete_restore::producer_progress::{
        original_restored_producer_report_storage_data, report_storage,
    };
    let report = original_restored_producer_report_storage_data(launch, maximum)?;
    let wire = report_storage::wire_projection(maximum)?;
    let report_projection = report_storage::projection(maximum)?;
    let objects = [
        crate::connection::OriginalContinuationContentExtent {
            maximum_payload_bytes: 65_536,
            media_type: "application/json",
        },
        crate::connection::OriginalContinuationContentExtent {
            maximum_payload_bytes: 65_536,
            media_type: "application/json",
        },
    ];
    let prefix = crate::connection::quote_original_packet_prefix_startup_storage_data(
        launch,
        crate::connection::OriginalPacketPrefixProjectionInput {
            terminal: &wire,
            original: &wire,
            objects: &objects,
            maximum_requested_bytes: maximum,
        },
    )?;
    let raw_upload =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            upload_bytes.max(1),
        )?;
    let upload_typed_arrays = mul(
        raw_upload.maximum_value_nodes,
        mul(
            4,
            size_of::<crate::reference_packet::common::PacketCommonOwner>(),
        )?,
    )?;
    let typed = sum(&[
        size_of::<PacketNativeRecord>(),
        size_of::<PacketNativeRestoredRecord>(),
        size_of::<PacketGrant>(),
        mul(4, sum(&[size_of::<PacketEvent>(), 128, 32])?)?,
        mul(6, sum(&[size_of::<PacketPublication>(), 128, 128, 32])?)?,
        128,
    ])?;
    let scratch = projection::counter_scratch_data()
        + crate::reference_packet::service::complete_restore::producer_progress::original_restored_producer_report_counter_scratch_data()
        + crate::connection::original_packet_prefix_startup_counter_scratch_data();
    let row = PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(sum(&[
            mul(8, typed)?,
            mul(8, report_projection.requested_total()?)?,
            prefix.source_owner_requested_bytes,
            prefix.exchange.requested_bytes()?,
            mul(8, upload_bytes)?,
            mul(3, raw_upload.value_dom_requested_bytes)?,
            size_of::<crate::client::OriginalRestoredSuffixHostAttempt>(),
        ])?)?,
        maximum_simultaneous_transient_bytes: quantity(sum(&[
            mul(8, typed)?,
            mul(8, report.maximum_simultaneous_transient_bytes_data())?,
            prefix.requested_bytes()?,
            mul(8, upload_bytes)?,
            mul(3, raw_upload.canonical_pass_requested_bytes()?)?,
            upload_typed_arrays,
            size_of::<crate::reference_packet::common::PacketNative5CommonGrant>(),
        ])?)?,
        declared_counter_scratch_bytes: quantity(scratch)?,
    };
    if usize::try_from(row.requested_peak_data()?).map_err(|_| invalid())? > maximum {
        return Err(invalid());
    }
    Ok(row)
}

/// Names actual quote, SDK, proof and report views before any fallible traversal.
pub fn original_restored_producer_lifecycle_counter_scratch_data() -> usize {
    size_of::<PacketRestoredProducerLifecycleInputs<'static>>()
        + size_of::<&PacketRestoredProducerLifecycleInputs<'static>>()
        + size_of::<PacketRestoredProducerLifecycleStorageData>()
        + size_of::<Result<PacketRestoredProducerLifecycleStorageData, ProviderError>>()
        + size_of::<PacketRestoredProducerPopulationData>()
        + size_of::<Result<PacketRestoredProducerPopulationData, ProviderError>>()
        + size_of::<projection::Projected>()
        + size_of::<Result<projection::Projected, ProviderError>>()
        + size_of::<OriginalSerializationStorageData>() * 3
        + size_of::<PacketNativeStartupAllocationRow>() * 2
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<PacketRestoredProducerOperationData<'static>>()
        + size_of::<PacketRestoredProducerArgumentsData<'static>>()
        + size_of::<&PacketNativeRestoredRecord>() * 2
        + size_of::<&PacketNativeRecord>() * 2
        + size_of::<&PacketInventory>() * 2
        + size_of::<&PacketGrant>()
        + size_of::<std::slice::Iter<'static, PacketEvent>>() * 2
        + size_of::<std::slice::Iter<'static, PacketPublication>>()
        + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>()
        + size_of::<[u8; 32]>() * 2
        + size_of::<[usize; 9]>()
        + crate::client::OriginalRestoredSuffixHostAttempt::counter_scratch_data()
        + super::producer_ingress::counter_scratch_data()
        + crate::reference_packet::service::complete_restore::producer_progress::original_restored_producer_progress_counter_scratch_data()
        + projection::counter_scratch_data()
        + native_closed_producer_action_counter_scratch_data()
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    terms.iter().try_fold(0usize, |total, term| {
        total.checked_add(*term).ok_or_else(invalid)
    })
}
fn mul(count: usize, bytes: usize) -> Result<usize, ProviderError> {
    count.checked_mul(bytes).ok_or_else(invalid)
}
fn quantity(bytes: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(bytes).map_err(|_| invalid())?))
}

pub(crate) fn native_closed_producer_action_counter_scratch_data() -> usize {
    size_of::<[crate::connection::OriginalContinuationContentExtent<'static>; 2]>()
        + size_of::<crate::connection::OriginalPacketPrefixProjectionInput<'static>>()
        + size_of::<crate::connection::OriginalPacketPrefixProjectionStorageData>()
        + size_of::<Result<crate::connection::OriginalPacketPrefixProjectionStorageData, ProviderError>>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<crate::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerReportStorageData>()
        + size_of::<Result<crate::reference_packet::service::complete_restore::producer_progress::PacketRestoredProducerReportStorageData, ProviderError>>()
        + size_of::<OriginalSerializationStorageData>() * 2
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<[usize; 8]>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + projection::counter_scratch_data()
        + crate::reference_packet::service::complete_restore::producer_progress::original_restored_producer_report_counter_scratch_data()
}

/// Borrows the complete fixed lifecycle quote without reconstructing authority.
pub struct PacketRestoredProducerLifecycleHistoricalData<'a> {
    original: &'a PacketRestoredProducerLifecycleStorageData,
}

impl PacketRestoredProducerLifecycleStorageData {
    /// Borrows every quoted axis, population field and exact quote identity.
    pub fn historical_data(&self) -> PacketRestoredProducerLifecycleHistoricalData<'_> {
        PacketRestoredProducerLifecycleHistoricalData { original: self }
    }

    /// Names both complete borrowed fixed quote projections and scalar loans.
    pub fn historical_counter_scratch_data() -> usize {
        PacketNativeRestoredSuffixStartupStorageData::historical_counter_scratch_data()
            + size_of::<PacketRestoredProducerLifecycleHistoricalData<'static>>()
            + size_of::<&PacketRestoredProducerLifecycleStorageData>()
            + size_of::<HistoricalPopulation<'static>>()
            + size_of::<&PacketRestoredProducerPopulationData>()
            + size_of::<&[u8; 32]>()
            + 2 * size_of::<&PacketNativeStartupAllocationRow>()
            + 15 * size_of::<&usize>()
    }
}

struct HistoricalPopulation<'a>(&'a PacketRestoredProducerPopulationData);

impl Serialize for HistoricalPopulation<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let PacketRestoredProducerPopulationData {
            pending_before,
            pending_after,
            completed,
            newborn,
            payload_bytes,
            event_id_bytes,
            operation_id_bytes,
        } = self.0;
        let mut state = serializer.serialize_struct("HistoricalProducerPopulation", 7)?;
        state.serialize_field("pending_before", pending_before)?;
        state.serialize_field("pending_after", pending_after)?;
        state.serialize_field("completed", completed)?;
        state.serialize_field("newborn", newborn)?;
        state.serialize_field("payload_bytes", payload_bytes)?;
        state.serialize_field("event_id_bytes", event_id_bytes)?;
        state.serialize_field("operation_id_bytes", operation_id_bytes)?;
        state.end()
    }
}

impl Serialize for PacketRestoredProducerLifecycleHistoricalData<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let PacketRestoredProducerLifecycleStorageData {
            startup,
            identity,
            population,
            ingress,
            action,
            host_retained,
            host_transient,
            source_retained,
            source_transient,
            maximum_report,
            originals,
            scratch,
            requested,
        } = self.original;
        let mut state = serializer.serialize_struct("HistoricalProducerLifecycleStorage", 14)?;
        state.serialize_field(
            "schema",
            "source-private.restored-producer-lifecycle-storage/1",
        )?;
        state.serialize_field("startup", &startup.historical_data())?;
        state.serialize_field("population", &HistoricalPopulation(population))?;
        state.serialize_field("identity", identity)?;
        state.serialize_field("ingress", ingress)?;
        state.serialize_field("action", action)?;
        state.serialize_field("host_retained", host_retained)?;
        state.serialize_field("host_transient", host_transient)?;
        state.serialize_field("source_retained", source_retained)?;
        state.serialize_field("source_transient", source_transient)?;
        state.serialize_field("maximum_report", maximum_report)?;
        state.serialize_field("originals", originals)?;
        state.serialize_field("scratch", scratch)?;
        state.serialize_field("requested", requested)?;
        state.end()
    }
}
