//! Projects complete common Producer outcomes without manufacturing a future result.
//!
//! The immutable two-event program supplies every possible publication and its
//! payload. Future coordinates and proof refs use their closed schema ranges.
//! This precredit DATA grants no scheduler, native or publication authority.

use super::*;
use crate::node_contract::StopReason;
use serde::{
    Serialize, Serializer,
    ser::{SerializeSeq, SerializeStruct},
};
use std::mem::size_of;

const MAXIMUM_ID: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Bounds complete common Outcome storage from the actual installed Producer.
///
/// The current Source, immutable program, actual target and descriptor loan
/// define this row. The matching action claim still authorizes every effect.
#[derive(Clone, Copy)]
pub struct OriginalRestoredProducerOutcomeConstructionData {
    source: *const PacketCompleteSemanticSource,
    target: *const ActivationRecord,
    requested: usize,
    encoded: usize,
    scratch: usize,
}

impl OriginalRestoredProducerOutcomeConstructionData {
    /// Returns cumulative typed, DOM, canonical and parse/conversion work.
    ///
    /// The independently named fixed counter scratch is additional.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }

    /// Returns the defining serialization-event upper extent of Outcome bytes.
    pub fn maximum_encoded_bytes_data(&self) -> usize {
        self.encoded
    }

    /// Returns independently named fixed projection and counter views.
    pub fn counter_scratch_bytes_data(&self) -> usize {
        self.scratch
    }

    pub(crate) fn authenticate_original_data(
        &self,
        source: &PacketCompleteSemanticSource,
        target: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        source.storage_origin_with_error::<RuntimeError>()?;
        if !std::ptr::eq(self.source, source) || !std::ptr::eq(self.target, target) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl PacketCompleteSemanticSource {
    /// Projects the full finite common Outcome before any restored execution.
    ///
    /// All program payloads are included, even when the next grant cannot reach
    /// them. No pending/history owner is discounted. Repeated operations retain
    /// independent rows; this producer does not renew native original credit.
    ///
    /// # Errors
    /// Refuses a foreign Source origin, another model family, an unsupported
    /// descriptor/owner shape, checked overflow, or the unchanged policy bound.
    pub fn original_restored_producer_outcome_construction_data(
        &self,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<OriginalRestoredProducerOutcomeConstructionData, RuntimeError> {
        let projection = self.original_restored_producer_outcome_projection_data(target)?;
        let typed_slot = [
            size_of::<OperationOutcome>(),
            size_of::<NativeSchedulingObservation>(),
            size_of::<NativePublication>(),
            size_of::<NativeProducerBound>(),
            size_of::<OwnerIdentity>(),
            size_of::<ContentRef>(),
            size_of::<Endpoint>(),
            size_of::<ProgressEvidence>(),
        ]
        .into_iter()
        .max()
        .ok_or(RuntimeError::ResourceLimit)?;
        let (requested, encoded) =
            NodeRuntime::original_restoration_coordinator_serialization_geometry_data(
                &projection,
                typed_slot,
                maximum,
            )?;
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(OriginalRestoredProducerOutcomeConstructionData {
            source: self,
            target,
            requested,
            encoded,
            scratch: Self::original_restored_producer_outcome_counter_scratch_data(),
        })
    }

    /// Borrows the exact future Outcome, route, request and full-ref sizing views.
    ///
    /// The returned serializer lends actual source/target children. Future ID,
    /// coordinate and proof fields use closed schema maxima, never live rights.
    ///
    /// # Errors
    /// Refuses foreign origin, another model or an unsupported target/route shape.
    pub fn original_restored_producer_outcome_projection_data<'a>(
        &'a self,
        target: &'a ActivationRecord,
    ) -> Result<OriginalRestoredProducerOutcomeProjection<'a>, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let CompletePacketOriginal::Producer(source) = &self.original else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let installation = self.installation();
        let [port] = installation.descriptor.ports.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let [lane] = port.lanes.as_slice() else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let mut matched = None;
        for owner in &target.owners {
            if owner.owner == installation.owner.owner.id {
                if matched.replace(owner).is_some() {
                    return Err(RuntimeError::ForeignAuthority);
                }
            }
        }
        let owner = matched.ok_or(RuntimeError::ForeignAuthority)?;
        let program = source.original_program_data();
        Ok(OriginalRestoredProducerOutcomeProjection {
            node: &installation.descriptor.id,
            owner,
            port: &port.id,
            lane: &lane.id,
            program,
            target,
        })
    }

    /// Names the actual borrowed serializers, layouts and complete result views.
    pub fn original_restored_producer_outcome_counter_scratch_data() -> usize {
        NodeRuntime::capture_serialization_counter_scratch_data()
            + size_of::<OriginalRestoredProducerOutcomeProjection<'static>>()
            + size_of::<OriginalRestoredProducerHistoricalInstallationData<'static>>()
            + size_of::<OriginalRestoredProducerHistoricalAdmissionData<'static>>()
            + size_of::<RouteProjection<'static>>()
            + size_of::<OperationRequest>()
            + size_of::<FutureScheduling<'static>>()
            + size_of::<FuturePublications<'static>>()
            + size_of::<FutureOutputs<'static>>()
            + size_of::<FuturePublication<'static>>()
            + size_of::<FutureBound<'static>>()
            + size_of::<FutureReference>() * 3
            + size_of::<FutureHash>() * 3
            + size_of::<ProgressEvidence>()
            + size_of::<Position>() * 3
            + size_of::<EndpointView<'static>>()
            + size_of::<OriginalRestoredProducerOutcomeConstructionData>()
            + size_of::<Result<OriginalRestoredProducerOutcomeConstructionData, RuntimeError>>()
            + size_of::<Result<(usize, usize), RuntimeError>>()
            + size_of::<Option<&OwnerIdentity>>()
            + size_of::<Result<&OwnerIdentity, RuntimeError>>()
            + size_of::<std::slice::Iter<'static, OwnerIdentity>>() * 2
            + size_of::<
                std::slice::Iter<'static, crucible_node_transport::reference_packet::PacketEvent>,
            >() * 2
            + size_of::<Option<&Bytes>>()
            + size_of::<&crucible_node_transport::reference_packet::PacketEvent>() * 2
            + size_of::<[FutureBound<'static>; 1]>()
            + size_of::<[&OwnerIdentity; 1]>()
            + size_of::<[Position; 0]>()
            + size_of::<[NativeExternalInputInventory; 0]>()
            + size_of::<[usize; 8]>()
            + size_of::<std::array::IntoIter<usize, 8>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Option<usize>>()
    }
}

#[derive(Serialize)]
struct FutureHash {
    algorithm: &'static str,
    domain: &'static str,
    digest: &'static str,
}

#[derive(Serialize)]
struct FutureReference {
    hash: FutureHash,
    length: U64,
    media_type: &'static str,
}

impl FutureReference {
    fn new(media_type: &'static str) -> Self {
        Self {
            hash: FutureHash {
                algorithm: "blake3-256",
                domain: "cnp.blob.v1",
                digest: HEX,
            },
            length: U64::new(u64::MAX),
            media_type,
        }
    }
}

fn future_position() -> Position {
    Position::new(U64::new(u64::MAX), U64::new(u64::MAX), Phase::Reaction)
}

/// Borrows one closed future common Outcome and its actual target route.
///
/// Serialization is prospective DATA only; this value carries no actual grant,
/// execution result, checkpoint or durable publication permission.
pub struct OriginalRestoredProducerOutcomeProjection<'a> {
    node: &'a Id,
    owner: &'a OwnerIdentity,
    port: &'a Id,
    lane: &'a Id,
    program: &'a crucible_node_transport::reference_packet::PacketProgramDefinition,
    target: &'a ActivationRecord,
}

impl OriginalRestoredProducerOutcomeProjection<'_> {
    /// Borrows the same actual target activation fields for a publication root.
    pub fn target_data(&self) -> &ActivationRecord {
        self.target
    }

    /// Borrows the closed route shape containing the actual node and target owner.
    pub fn route_data(&self) -> impl Serialize + '_ {
        RouteProjection {
            node: self.node,
            owners: [self.owner],
        }
    }

    /// Returns the closed largest supported request shape as inert sizing DATA.
    pub fn request_data(&self) -> OperationRequest {
        OperationRequest::ExactRun {
            start: future_position(),
            limit: future_position(),
            boundary_policy: ExactBoundaryPolicy::HorizonPark,
        }
    }

    /// Borrows the complete closed common Outcome serializer.
    pub fn outcome_data(&self) -> &impl Serialize {
        self
    }

    /// Returns the normative future Source report's full JSON reference view.
    pub fn report_ref_data(&self) -> impl Serialize {
        FutureReference::new("application/json")
    }
}

#[derive(Serialize)]
struct RouteProjection<'a> {
    node: &'a Id,
    owners: [&'a OwnerIdentity; 1],
}

impl Serialize for OriginalRestoredProducerOutcomeProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OperationOutcome", 6)?;
        state.serialize_field("operation", MAXIMUM_ID)?;
        state.serialize_field("node", self.node)?;
        state.serialize_field("owners", &[self.owner])?;
        state.serialize_field(
            "progress",
            &ProgressEvidence::Exact {
                reached: future_position(),
                stop: StopReason::HorizonPark,
            },
        )?;
        state.serialize_field("retained_outputs", &FutureOutputs(self.program))?;
        state.serialize_field("scheduling", &Some(FutureScheduling(self)))?;
        state.end()
    }
}

fn output_count(
    program: &crucible_node_transport::reference_packet::PacketProgramDefinition,
) -> usize {
    let mut count = 0;
    for event in &program.events {
        if event.payload.is_some() {
            count += 1;
        }
    }
    count
}

struct FutureOutputs<'a>(&'a crucible_node_transport::reference_packet::PacketProgramDefinition);

impl Serialize for FutureOutputs<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = output_count(self.0);
        let mut seq = serializer.serialize_seq(Some(count))?;
        for event in &self.0.events {
            if event.payload.is_some() {
                seq.serialize_element(&event.id)?;
            }
        }
        seq.end()
    }
}

struct FutureScheduling<'a>(&'a OriginalRestoredProducerOutcomeProjection<'a>);

impl Serialize for FutureScheduling<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("NativeSchedulingObservation", 9)?;
        state.serialize_field("node", self.0.node)?;
        state.serialize_field("owners", &[self.0.owner])?;
        state.serialize_field("reached", &future_position())?;
        state.serialize_field("closed_prefix", &future_position())?;
        state.serialize_field(
            "bounds",
            &[FutureBound {
                producer: self.0.node,
                bound: NativeOutputBound::At(future_position()),
                proof_ref: FutureReference::new("application/json"),
            }],
        )?;
        state.serialize_field("publications", &FuturePublications(self.0))?;
        state.serialize_field("input_progress", &Option::<NativeInputProgress>::None)?;
        state.serialize_field("external_inputs", &[] as &[NativeExternalInputInventory])?;
        state.serialize_field("proof_ref", &FutureReference::new("application/json"))?;
        state.end()
    }
}

#[derive(Serialize)]
struct FutureBound<'a> {
    producer: &'a Id,
    bound: NativeOutputBound,
    proof_ref: FutureReference,
}

struct FuturePublications<'a>(&'a OriginalRestoredProducerOutcomeProjection<'a>);

impl Serialize for FuturePublications<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = output_count(self.0.program);
        let mut seq = serializer.serialize_seq(Some(count))?;
        for event in &self.0.program.events {
            if let Some(payload) = &event.payload {
                seq.serialize_element(&FuturePublication {
                    publication_id: &event.id,
                    endpoint: EndpointView {
                        node_id: self.0.node,
                        port_id: self.0.port,
                        lane_id: self.0.lane,
                    },
                    native_sequence: U64::new(u64::MAX),
                    publication: event.completion,
                    evaluation: Some(event.evaluation),
                    causal_parents: [],
                    payload: FutureReference::new("application/octet-stream"),
                    payload_bytes: payload.as_slice(),
                })?;
            }
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct EndpointView<'a> {
    node_id: &'a Id,
    port_id: &'a Id,
    lane_id: &'a Id,
}

#[derive(Serialize)]
struct FuturePublication<'a> {
    publication_id: &'a Id,
    endpoint: EndpointView<'a>,
    native_sequence: U64,
    publication: Position,
    evaluation: Option<Position>,
    causal_parents: [Position; 0],
    payload: FutureReference,
    payload_bytes: &'a [u8],
}

impl PacketCompleteSemanticSource {
    pub(crate) fn original_restored_producer_native_original_limit_data(
        &self,
    ) -> Result<usize, RuntimeError> {
        let startup = self.original_restored_suffix_observation_startup_data()?;
        usize::try_from(startup.reservation_data().maximum_originals.get())
            .map_err(|_| RuntimeError::ResourceLimit)
    }
}

impl PacketCompleteSemanticSource {
    /// Maps an already Source-authenticated completed native Producer grant.
    ///
    /// This constructs result DATA only. The caller must retain it under the
    /// real action claim and SourceRead and authenticate the complete B proof;
    /// neither this helper nor the returned DTO can issue an operation grant.
    pub(crate) fn original_restored_producer_mapped_outcome_data(
        &self,
        original: &OperationAdmission,
        restored: &crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        producer: &crucible_node_transport::reference_packet::control::PacketNativeRecord,
        measurement: &ContentRef,
    ) -> Result<OperationOutcome, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let CompletePacketOriginal::Producer(source) = &self.original else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        if original.inputs().is_some() {
            return Err(RuntimeError::InvalidReceipt);
        }
        let install = self.installation();
        Self::original_restored_producer_historical_mapped_outcome_data(
            OriginalRestoredProducerHistoricalAdmissionData {
                operation: original.token().operation(),
                route: original.token().route(),
                request: original.request(),
                world_binding: &original.activation().record().world_binding_hash,
                activation_owners: &original.activation().record().owners,
            },
            OriginalRestoredProducerHistoricalInstallationData {
                descriptor: &install.descriptor,
                owner: &install.owner.owner.id,
                incarnation: &install.binding.authority.incarnation_id,
                generation: install.binding.authority.owner_generation,
                world_binding: &install.world_binding_hash,
                program: source.original_program_data(),
            },
            restored,
            producer,
            measurement,
        )
    }
}

impl OriginalRestoredProducerOutcomeProjection<'_> {
    pub(crate) fn endpoint_parts_data(&self) -> (&Id, &Id, &Id) {
        (self.node, self.port, self.lane)
    }
}

impl PacketCompleteSemanticSource {
    /// Maps a separately authenticated grant-free post-retirement checkpoint.
    ///
    /// Its caller supplies B's complete Retire/current-Observe correspondence
    /// under the same SourceRead. No old held-model equality is relaxed here.
    pub(crate) fn original_restored_producer_checkpoint_scheduling_data(
        &self,
        world: &WorldActivation,
        restored: &crucible_node_transport::reference_packet::service::complete_restore::PacketNativeRestoredRecord,
        producer: &crucible_node_transport::reference_packet::control::PacketNativeRecord,
        measurement: &ContentRef,
    ) -> Result<NativeSchedulingObservation, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        let CompletePacketOriginal::Producer(source) = &self.original else {
            return Err(RuntimeError::UnsupportedFacet);
        };
        let install = self.installation();
        Self::original_restored_producer_historical_checkpoint_scheduling_data(
            &world.record().world_binding_hash,
            &world.record().owners,
            OriginalRestoredProducerHistoricalInstallationData {
                descriptor: &install.descriptor,
                owner: &install.owner.owner.id,
                incarnation: &install.binding.authority.incarnation_id,
                generation: install.binding.authority.owner_generation,
                world_binding: &install.world_binding_hash,
                program: source.original_program_data(),
            },
            restored,
            producer,
            measurement,
        )
    }
}

#[path = "restored_producer_outcome/historical.rs"]
mod historical;
pub(crate) use historical::{
    OriginalRestoredProducerHistoricalAdmissionData,
    OriginalRestoredProducerHistoricalInstallationData,
};
