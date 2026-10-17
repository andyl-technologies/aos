//! Enrolls unpredictable native fields before inspecting common completion reports.
//!
//! Only an opaque original typed source window can construct a retained seal.
//! Its deterministic input/output oracle was frozen before launch. Kernel,
//! namespace, realization and registrar authentication remain conjunctive in
//! the owning policy; this collector grants no operation or accepted class.

use std::{
    cell::{Ref, RefCell},
    rc::Rc,
};

use crucible::node_adapters::cnp::OriginalRuntimeLineage;
use crucible::node_contract::{InputProvenanceClosure, OriginalInputLineage};
use crucible::node_scheduling::InputIdentity;
use crucible::node_scheduling::RuntimeInputBatch;
use crucible_node_contract::{
    ContentRef, InputBatch, ObservationBatch, Phase, StopReceipt, U64, canonical,
};
use crucible_node_provider::{
    ProviderError,
    reference_device::DeviceReceipt,
    reference_lineage::{LineageStage, NativeLineageReceipt},
};
use serde::Serialize;

use super::programme::{PRODUCER_BYTES, TypedReaderProgramme, count, invalid};

const MAXIMUM_OBJECTS: usize = 80;
const MAXIMUM_BYTES: usize = 1024 * 1024;
const MAXIMUM_EDGES: usize = 4096;

/// Retains one original body and complete source-selected direct dependencies.
pub struct TypedReaderOriginalRow {
    /// Binds the unchanged full original body and its exact media role.
    pub reference: ContentRef,
    /// Retains the complete unchanged original bytes.
    pub bytes: Vec<u8>,
    /// Lists every direct source-selected edge, including external producer roles.
    pub dependencies: Vec<ContentRef>,
}

/// Retains source-native expectations independently of common completion reports.
///
/// This type has no public constructor, clone or deserializer. It is produced
/// only while the original owning controller lends its authenticated window.
/// Its receipt fields remain original observations, rather than predeclared
/// physical measurements or an assertion that publication was already ACKed.
pub struct OriginalTypedWindowSeal {
    pub(super) case: String,
    stage: LineageStage,
    native: NativeLineageReceipt,
    pub(super) controlled: DeviceReceipt,
    pub(super) stop: StopReceipt,
    pub(super) observation: ObservationBatch,
    pub(super) measurement: ContentRef,
    pub(super) rows: Vec<TypedReaderOriginalRow>,
    pub(super) input: InputBatch,
    pub(super) consumed: Vec<InputIdentity>,
}

impl OriginalTypedWindowSeal {
    /// Returns the independently predeclared original case ID.
    pub fn case(&self) -> &str {
        &self.case
    }

    /// Returns the actual native stage, including every ordered consumed byte.
    pub fn stage(&self) -> &LineageStage {
        &self.stage
    }

    /// Returns the actual native close receipt and checksum ancestry.
    pub fn native(&self) -> &NativeLineageReceipt {
        &self.native
    }

    /// Returns the independently measured original controlled-window receipt.
    pub fn controlled(&self) -> &DeviceReceipt {
        &self.controlled
    }

    /// Returns the complete original stop scope from the source callback.
    pub fn stop(&self) -> &StopReceipt {
        &self.stop
    }

    /// Returns the complete original ordered public publication batch.
    pub fn observation(&self) -> &ObservationBatch {
        &self.observation
    }

    /// Returns the actual original measurement root.
    pub fn measurement(&self) -> &ContentRef {
        &self.measurement
    }

    /// Returns complete selected body/direct rows, preserving external references.
    pub fn rows(&self) -> &[TypedReaderOriginalRow] {
        &self.rows
    }
}

/// Reserves nine source-native oracle holders before any Child allocation.
///
/// Installation does not authenticate the namespace or host launch authority.
/// An installed fixture must first conjoin those independent premises and the
/// owning kernel/registrar checks before invoking source enrollment. Later host
/// result authentication must borrow these originals before accepting a report.
pub struct TypedReaderNativeOracles {
    pub(super) programme: Rc<TypedReaderProgramme>,
    seals: RefCell<Vec<OriginalTypedWindowSeal>>,
}

impl TypedReaderNativeOracles {
    /// Reserves the complete finite original source-holder roster before launch.
    ///
    /// # Errors
    /// Refuses unavailable holder capacity without starting any native work.
    pub fn new(programme: Rc<TypedReaderProgramme>) -> Result<Self, ProviderError> {
        let mut seals = Vec::new();
        seals.try_reserve_exact(9).map_err(|_| credit())?;
        Ok(Self {
            programme,
            seals: RefCell::new(seals),
        })
    }

    /// Enrolls a held source-native closure against the frozen semantic programme.
    ///
    /// This runs inside the original source callback, before a host collector
    /// inspects common completion reports. Full encoded metadata/body/edge credit
    /// precedes owned copies. Refusal retains the original source and its native
    /// Unknown/held custody through the enclosing owning policy.
    ///
    /// # Errors
    /// Refuses foreign grants, owners, input bytes, checksums, duplicate changed
    /// originals, unavailable predecessors, malformed full bodies or exhausted
    /// nine-window/body/direct-edge capacity. It performs no ACK or native effect.
    pub fn enroll(&self, original: &OriginalRuntimeLineage<'_>) -> Result<(), ProviderError> {
        let source = original.source();
        let stage = source.native_stage();
        let native = source.native_receipt();
        let node = &original.operation().token().route().node;
        let planned = self.programme.window(node, stage.grant.quantum)?;
        let peer = self.programme.peer(node)?;
        if original.operation().request() != &planned.request
            || original.operation().token().operation() != &planned.operation
            || stage.grant.window_id != planned.window
            || stage.grant.input_batch_id != planned.batch
            || stage.grant.owner_id != peer.owner
            || stage.grant.incarnation_id != peer.incarnation
            || stage.grant.generation.get() != 1
            || native.checksum_before != planned.checksum_before
            || native.output != planned.output
            || source.controlled_receipt().output != planned.output
            || source.stop().operation_id != planned.operation
            || stage.entries.len() != planned.producers.len()
            || stage.input.len() != PRODUCER_BYTES.len() * planned.producers.len()
            || original
                .input()
                .deliveries()
                .iter()
                .map(|delivery| &delivery.producer)
                .ne(planned.producers.iter())
        {
            return Err(invalid());
        }
        let (parts, remainder) = stage.input.as_chunks::<{ PRODUCER_BYTES.len() }>();
        if !remainder.is_empty() {
            return Err(invalid());
        }
        for part in parts {
            if part != PRODUCER_BYTES {
                return Err(invalid());
            }
        }
        let [event] = source.observation().events.as_slice() else {
            return Err(invalid());
        };
        let output_bytes = json(&planned.output)?;
        event.payload.verify(&output_bytes)?;

        let evidence = source.measurement_evidence(MAXIMUM_OBJECTS, MAXIMUM_BYTES)?;
        let mut bytes = 0usize;
        let mut edges = 0usize;
        for row in evidence.objects() {
            bytes = bytes
                .checked_add(row.bytes().len())
                .filter(|n| *n <= MAXIMUM_BYTES)
                .ok_or_else(credit)?;
            edges = edges
                .checked_add(row.dependencies().len())
                .filter(|n| *n <= MAXIMUM_EDGES)
                .ok_or_else(credit)?;
            row.reference().verify(row.bytes())?;
        }
        let mut seals = self.seals.try_borrow_mut().map_err(|_| invalid())?;
        if let Some(old) = seals.iter().find(|old| old.case == planned.case) {
            return if old.native == *native
                && old.stage == *stage
                && old.controlled == *source.controlled_receipt()
                && old.stop == *source.stop()
                && old.observation == *source.observation()
                && old.measurement == *source.measurement_reference()
                && old.input == *source.input_batch()
                && old
                    .consumed
                    .iter()
                    .map(|identity| (&identity.producer, identity.source_sequence))
                    .eq(original
                        .input()
                        .deliveries()
                        .iter()
                        .map(|delivery| (&delivery.producer, delivery.source_sequence)))
                && old.rows.len() == evidence.objects().len()
                && old
                    .rows
                    .iter()
                    .zip(evidence.objects())
                    .all(|(old, current)| {
                        old.reference == *current.reference()
                            && old.bytes == current.bytes()
                            && old.dependencies == current.dependencies()
                    })
            {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        if seals.len() >= 9 {
            return Err(credit());
        }
        let previous = seals.iter().find(|old| {
            old.stage.grant.owner_id == peer.owner
                && old.stage.grant.quantum.get().checked_add(1) == Some(stage.grant.quantum.get())
        });
        native.validate_against(stage, previous.map(|old| &old.native))?;

        #[derive(Serialize)]
        struct Metadata<'a> {
            stage: &'a LineageStage,
            native: &'a NativeLineageReceipt,
            controlled: &'a DeviceReceipt,
            stop: &'a StopReceipt,
            observation: &'a ObservationBatch,
            measurement: &'a ContentRef,
        }
        count(
            &Metadata {
                stage,
                native,
                controlled: source.controlled_receipt(),
                stop: source.stop(),
                observation: source.observation(),
                measurement: source.measurement_reference(),
            },
            65536,
        )?;
        // The source's accepted batch and coordinator identities are retained
        // before a later common completion can be inspected as an oracle.
        count(source.input_batch(), 65536)?;
        if original.input().deliveries().len() > 2 {
            return Err(credit());
        }
        count(&BorrowedRows(&evidence), 65536)?;

        let mut rows = Vec::new();
        rows.try_reserve_exact(evidence.objects().len())
            .map_err(|_| credit())?;
        for row in evidence.objects() {
            let mut body = Vec::new();
            body.try_reserve_exact(row.bytes().len())
                .map_err(|_| credit())?;
            body.extend_from_slice(row.bytes());
            let mut dependencies = Vec::new();
            dependencies
                .try_reserve_exact(row.dependencies().len())
                .map_err(|_| credit())?;
            dependencies.extend_from_slice(row.dependencies());
            rows.push(TypedReaderOriginalRow {
                reference: row.reference().clone(),
                bytes: body,
                dependencies,
            });
        }
        seals.push(OriginalTypedWindowSeal {
            case: planned.case.clone(),
            stage: stage.clone(),
            native: native.clone(),
            controlled: source.controlled_receipt().clone(),
            stop: source.stop().clone(),
            observation: source.observation().clone(),
            measurement: source.measurement_reference().clone(),
            rows,
            input: source.input_batch().clone(),
            consumed: original
                .input()
                .deliveries()
                .iter()
                .map(|delivery| InputIdentity {
                    producer: delivery.producer.clone(),
                    source_sequence: delivery.source_sequence,
                })
                .collect(),
        });
        Ok(())
    }

    /// Borrows the original source-native seal; caller-supplied reports cannot insert it.
    ///
    /// # Errors
    /// Refuses an unenrolled case or a simultaneous original enrollment callback.
    pub fn original(&self, case: &str) -> Result<Ref<'_, OriginalTypedWindowSeal>, ProviderError> {
        let seals = self.seals.try_borrow().map_err(|_| invalid())?;
        Ref::filter_map(seals, |seals| seals.iter().find(|seal| seal.case == case))
            .map_err(|_| invalid())
    }

    /// Checks the four declared producer deliveries before the consumer's Stage.
    ///
    /// Each delivery must refer to its original producer's preceding window,
    /// exact publication Event, measurement and complete source scope. Equal
    /// payload bytes from another producer/window cannot replace that identity.
    /// The owning policy additionally checks every producer's current kernel,
    /// registrar, full provenance objects and source-issued lineage association.
    ///
    /// # Errors
    /// Refuses a foreign cut/batch, omitted or reordered delivery, unsealed
    /// producer, changed full origin, payload or source proof. It copies no
    /// producer body and neither stages nor acknowledges native work.
    pub fn authenticate_inputs(
        &self,
        input: &RuntimeInputBatch,
        provenance: &InputProvenanceClosure,
        lineage: &OriginalInputLineage,
    ) -> Result<(), ProviderError> {
        let time = input
            .cutoff()
            .time_ps
            .get()
            .checked_sub(1)
            .ok_or_else(invalid)?;
        if time % 1000 != 0
            || input.cutoff().microstep.get() != 0
            || input.cutoff().phase != Phase::BoundaryControl
        {
            return Err(invalid());
        }
        let planned = self.programme.window(input.node(), U64::new(time / 1000))?;
        let original = lineage.original();
        if input.batch() != &planned.batch
            || input.stage_operation() != &planned.stage
            || input.deliveries().len() != planned.producers.len()
            || lineage.publications().len() != planned.producers.len()
            || original.deliveries() != input.deliveries()
            || original.payloads() != input.payloads()
            || !original.activation().same_authority(input.activation())
            || !provenance.activation().same_authority(input.activation())
            || provenance.inventory() != input.inventory()
            || provenance.batch() != input.batch()
            || provenance.stage_operation() != input.stage_operation()
            || provenance.node() != input.node()
        {
            return Err(invalid());
        }
        let seals = self.seals.try_borrow().map_err(|_| invalid())?;
        for ((delivery, claim), producer) in input
            .deliveries()
            .iter()
            .zip(lineage.publications())
            .zip(&planned.producers)
        {
            let preceding = self.programme.window(
                producer,
                U64::new(planned.quantum.get().checked_sub(1).ok_or_else(invalid)?),
            )?;
            let seal = seals
                .iter()
                .find(|seal| seal.case == preceding.case)
                .ok_or_else(invalid)?;
            let [event] = seal.observation.events.as_slice() else {
                return Err(invalid());
            };
            let stop = &seal.stop;
            let origin = &claim.origin;
            if delivery.producer != *producer
                || delivery.publication_id != event.id
                || delivery.native_sequence != event.source_sequence
                || delivery.payload != event.payload
                || delivery.provenance_ref != seal.measurement
                || claim.event != *event
                || claim.published != canonical::content_ref(&json(event)?, "application/json")?
                || origin.owner_binding_hash != stop.owner_binding_hash
                || origin.execution_owner_id != stop.execution_owner_id
                || origin.session_id != stop.session_id
                || origin.world_binding_hash != stop.world_binding_hash
                || origin.activation_id != stop.activation_id
                || origin.world_generation != stop.world_generation
                || origin.incarnation_id != stop.incarnation_id
                || origin.owner_generation != stop.owner_generation
                || origin.operation_id != preceding.operation
                || origin.grant_id != preceding.window
                || origin.measurement != seal.measurement
                || origin.observation_batch != stop.observation_batch
                || origin.stop_receipt != canonical::content_ref(&json(stop)?, "application/json")?
            {
                return Err(invalid());
            }
            let body = input
                .payloads()
                .iter()
                .find(|body| body.reference == event.payload)
                .ok_or_else(invalid)?;
            if body.bytes != PRODUCER_BYTES {
                return Err(invalid());
            }
            body.reference.verify(&body.bytes)?;
        }
        Ok(())
    }
}

fn json(value: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    count(value, 65536)?;
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    Ok(canonical::canonical_json(&value)?)
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("typed source-native oracle custody credit")
}

/// Counts full row metadata without allocating a projected reference vector.
struct BorrowedRows<'a>(&'a crucible_node_provider::client::OriginalLineageEvidence<'a>);
impl serde::Serialize for BorrowedRows<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence = serializer.serialize_seq(Some(self.0.objects().len()))?;
        for row in self.0.objects() {
            sequence.serialize_element(&(row.reference(), row.dependencies()))?;
        }
        sequence.end()
    }
}
