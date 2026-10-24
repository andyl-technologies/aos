//! Projects original paused-restoration storage without minting an activation.
//!
//! Archived owners and future target records are borrowed DATA. Every map,
//! collect/sort bank and independent clone has its own requested term. Original
//! snapshot validation and scheduler construction still run at their old sites.

use super::*;
use crate::node_contract::{
    NodeRuntime, OriginalLineageRuntimeRecord, RuntimeError, RuntimeOwnedStorage,
};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::mem::{align_of, size_of};

/// Borrows the prospective encoding of the same paused scheduler's public data.
///
/// This range projection has no activation, ACK, epoch or restoration authority.
/// It is only supplied to a closed allocation counter. The actual publisher
/// later encodes the real PreparedSchedulingRestore at its original call site.
pub(crate) struct OriginalSchedulingRestorationPublicationProjection<'a> {
    record: &'a OriginalLineageRuntimeRecord,
    snapshot: &'a SchedulingSnapshot,
    target: &'a ActivationRecord,
}

struct FreshAcknowledgements<'a> {
    record: &'a OriginalLineageRuntimeRecord,
    target: &'a ActivationRecord,
}

struct FreshAcknowledgement<'a> {
    original: &'a crate::node_scheduling::NativeInputAcknowledgement,
    target: &'a ActivationRecord,
}

struct FreshProof;

struct FreshHash;

impl Serialize for FreshProof {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut value = serializer.serialize_struct("ContentRef", 3)?;
        // The selected scope constructor uses this exact public grammar. The
        // unknown digest has64 unescaped hexadecimal bytes; no hash is minted.
        value.serialize_field("hash", &FreshHash)?;
        value.serialize_field("length", &U64::new(u64::MAX))?;
        value.serialize_field("media_type", "application/json")?;
        value.end()
    }
}

impl Serialize for FreshHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut hash = serializer.serialize_struct("HashRef", 3)?;
        hash.serialize_field("algorithm", "blake3-256")?;
        hash.serialize_field("domain", "cnp.blob.v1")?;
        hash.serialize_field(
            "digest",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )?;
        hash.end()
    }
}

impl Serialize for FreshAcknowledgement<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut ack = serializer.serialize_struct("NativeInputAcknowledgement", 7)?;
        ack.serialize_field("stage_operation", &self.original.stage_operation)?;
        ack.serialize_field("batch", &self.original.batch)?;
        ack.serialize_field("node", &self.original.node)?;
        // A full genuine target roster bounds the actual selected route subset.
        ack.serialize_field("owners", &self.target.owners)?;
        ack.serialize_field("inventory", &self.original.inventory)?;
        ack.serialize_field("cutoff", &self.original.cutoff)?;
        ack.serialize_field("proof_ref", &FreshProof)?;
        ack.end()
    }
}

impl Serialize for FreshAcknowledgements<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let count = self
            .record
            .inputs
            .iter()
            .filter(|input| input.acknowledgement.is_some())
            .count();
        let mut acknowledgements = serializer.serialize_seq(Some(count))?;
        for input in &self.record.inputs {
            if let Some(original) = &input.acknowledgement {
                acknowledgements.serialize_element(&FreshAcknowledgement {
                    original,
                    target: self.target,
                })?;
            }
        }
        acknowledgements.end()
    }
}

impl Serialize for OriginalSchedulingRestorationPublicationProjection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        (
            (
                &self.target.generation,
                &self.target.activation_id,
                &self.target.world_binding_hash,
                &self.target.owners,
                &self.target.boundary,
            ),
            self.snapshot,
            FreshAcknowledgements {
                record: self.record,
                target: self.target,
            },
            Option::<bool>::None,
        )
            .serialize(serializer)
    }
}

impl PreparedSchedulingRestore {
    /// Borrows the closed range projection used before its actual preparation.
    ///
    /// # Errors
    /// Refuses unsupported epoch/external/combined editions, absent historical
    /// ACK correspondence or another recorded world. No scheduler is created.
    pub(crate) fn original_lineage_publication_projection_data<'a>(
        record: &'a OriginalLineageRuntimeRecord,
        snapshot: &'a SchedulingSnapshot,
        target: &'a ActivationRecord,
    ) -> Result<OriginalSchedulingRestorationPublicationProjection<'a>, RuntimeError> {
        if record.schema_version != 7
            || snapshot.schema_version != 1
            || snapshot.original_epochs.is_some()
            || !snapshot.external_closed_prefixes.is_empty()
            || snapshot.world_binding_hash != target.world_binding_hash
            || snapshot.input_batches.iter().any(|batch| {
                !record.inputs.iter().any(|input| {
                    input.stage_operation == batch.stage_operation
                        && input.acknowledgement.is_some() == batch.acknowledgement.is_some()
                })
            })
        {
            return Err(RuntimeError::UnsupportedFacet);
        }
        Ok(OriginalSchedulingRestorationPublicationProjection {
            record,
            snapshot,
            target,
        })
    }
}

impl PreparedSchedulingRestore {
    /// Counts the same actually retained paused owner before a Window loan.
    ///
    /// Inline root storage is included conservatively even when the enclosing
    /// Window already counts its Option slot. Every actual target, snapshot and
    /// ACK capacity is visited independently; construction DATA is not reused.
    ///
    /// # Errors
    /// Refuses unsupported epoch/external-prefix owners, checked overflow or a
    /// requested owner total above `maximum`. No scheduler or callback runs.
    pub(crate) fn original_retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        let Self {
            target,
            snapshot,
            input_acknowledgements,
            epochs,
        } = self;
        if epochs.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let mut counter = Requested {
            bytes: size_of::<Self>(),
            maximum,
        };
        counter.add(0)?;
        counter.owned(target)?;
        counter.owned(snapshot)?;
        counter.owned(input_acknowledgements)?;
        Ok(counter.bytes)
    }

    /// Copies inert paused DATA while preserving the original retained owner.
    ///
    /// The selected Window authenticates and preadmits this independent copy
    /// before calling. A failed consuming installation may drop this duplicate;
    /// the same original target, snapshot and ACK owners remain in that Window.
    /// No activation, permission, native claim or scheduling epoch is duplicated.
    ///
    /// # Errors
    /// Refuses unsupported epochs or external-prefix owners and actual backing
    /// exceeding the independently admitted `maximum`, before any clone.
    pub(crate) fn duplicate_original_retained_for_installation_data(
        &self,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        self.original_retained_requested_storage_precredit_data(maximum)?;
        let Self {
            target,
            snapshot,
            input_acknowledgements,
            epochs: _,
        } = self;
        Ok(Self {
            target: target.clone(),
            snapshot: snapshot.clone(),
            input_acknowledgements: input_acknowledgements.clone(),
            epochs: None,
        })
    }

    /// Names the clone's complete payload, return and borrowed field views.
    pub(crate) fn original_retained_installation_duplicate_counter_scratch_data() -> usize {
        Self::original_retained_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<ActivationRecord>()
            + size_of::<SchedulingSnapshot>()
            + size_of::<Vec<crate::node_scheduling::NativeInputAcknowledgement>>()
            + size_of::<(
                &ActivationRecord,
                &SchedulingSnapshot,
                &Vec<crate::node_scheduling::NativeInputAcknowledgement>,
            )>()
            + size_of::<Option<&crate::node_scheduling::NativeInputAcknowledgement>>()
            + size_of::<std::slice::Iter<'static, crate::node_contract::OriginalLineageInputRecord>>(
            )
            + size_of::<(
                &OriginalLineageRuntimeRecord,
                &SchedulingSnapshot,
                &ActivationRecord,
            )>()
            + 2 * size_of::<usize>()
    }

    /// Prices the independent inert clone before any paused owner exists.
    ///
    /// The same source snapshot and target are authenticated by the caller.
    /// Fresh ACKs preserve saved identities and inventory, replace only their
    /// validated target-owner subset and use the closed fresh proof grammar.
    /// Original Window owners and the legacy consumer's later scheduler are
    /// funded independently. There is no sharing or successful-install refund.
    ///
    /// # Errors
    /// Refuses unsupported source editions/correspondence, arithmetic overflow
    /// or requested clone backing above `maximum` before construction.
    pub(crate) fn original_lineage_retained_installation_duplicate_storage_data(
        record: &OriginalLineageRuntimeRecord,
        snapshot: &SchedulingSnapshot,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        Self::original_lineage_publication_projection_data(record, snapshot, target)?;
        let mut counter = Requested { bytes: 0, maximum };
        counter.add(size_of::<Self>())?;
        counter.owned(snapshot)?;
        counter.owned(target)?;
        for input in &record.inputs {
            if let Some(ack) = &input.acknowledgement {
                counter.slots::<crate::node_scheduling::NativeInputAcknowledgement>(1)?;
                fresh_ack_backing(ack, target, &mut counter)?;
            }
        }
        Ok(counter.bytes)
    }

    /// Names defining owned-counter payload/return views before the actual walk.
    pub(crate) fn original_retained_counter_scratch_data() -> usize {
        crate::node_contract::opaque_owner_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Requested>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<std::slice::Iter<'static, crate::node_scheduling::NativeInputAcknowledgement>>(
            )
    }
}

struct Requested {
    bytes: usize,
    maximum: usize,
}

impl Requested {
    fn add(&mut self, next: usize) -> Result<(), RuntimeError> {
        self.bytes = self
            .bytes
            .checked_add(next)
            .filter(|n| *n <= self.maximum)
            .ok_or(RuntimeError::ResourceLimit)?;
        Ok(())
    }

    fn owned<T: RuntimeOwnedStorage + ?Sized>(&mut self, value: &T) -> Result<(), RuntimeError> {
        self.add(value.owned_storage()?)
    }

    fn slots<T>(&mut self, count: usize) -> Result<(), RuntimeError> {
        self.add(
            count
                .checked_mul(size_of::<T>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )
    }

    fn tree<K, V>(&mut self, count: usize, collect: bool) -> Result<(), RuntimeError> {
        self.add(NodeRuntime::capture_protocol_tree_storage(
            1,
            count,
            size_of::<K>()
                .checked_add(size_of::<V>())
                .ok_or(RuntimeError::ResourceLimit)?,
            align_of::<K>().max(align_of::<V>()),
            self.maximum,
        )?)?;
        if collect && count > 0 {
            // FromIterator's Vec and optional stable-sort heap coexist with the
            // growing BTree.4*count covers input growth and both sort branches;
            // the minimum48-slot drift scratch is explicit, not tree slack.
            self.slots::<(K, V)>(
                count
                    .checked_mul(4)
                    .ok_or(RuntimeError::ResourceLimit)?
                    .max(48),
            )?;
        }
        Ok(())
    }

    fn key_clones<T: RuntimeOwnedStorage + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), RuntimeError> {
        self.owned(value)?;
        self.owned(value)
    }
}

fn fresh_ack_backing(
    saved: &crate::node_scheduling::NativeInputAcknowledgement,
    target: &ActivationRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.owned(&saved.node)?;
    counter.owned(&saved.stage_operation)?;
    counter.owned(&saved.batch)?;
    counter.owned(&saved.inventory)?;
    counter.owned(&target.owners)?;
    // Exact selected scope proof grammar; the original native response and its
    // pre-validation capacities remain separately funded by the Source owner.
    counter.add("blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len())
}

fn validation_storage(
    graph: &AdmittedGraph,
    runtime: &OriginalLineageRuntimeRecord,
    snapshot: &SchedulingSnapshot,
    target: &ActivationRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    // validate_saved_profile: graph/source/target owner sets; comparison sets
    // for positions and producers remain independent simultaneous allocations.
    counter.tree::<Id, ()>(target.owners.len(), true)?;
    counter.tree::<Id, ()>(snapshot.source_owners.len(), true)?;
    counter.tree::<Id, ()>(target.owners.len(), true)?;
    for owner in &target.owners {
        counter.key_clones(&owner.owner)?;
    }
    for owner in &snapshot.source_owners {
        counter.owned(&owner.owner)?;
    }
    counter.tree::<Id, (QuantumGrid, ExecutionPolicy)>(graph.owners().count(), false)?;
    counter.tree::<Id, Id>(graph.node_ids().count(), false)?;
    for node in graph.node_ids() {
        let binding = graph.binding(node).ok_or(RuntimeError::UnknownNode)?;
        let policy = graph
            .operating_policy(node)
            .ok_or(RuntimeError::UnsupportedFacet)?;
        counter.key_clones(policy)?; // comparison clone and retained contract.
        counter.key_clones(node)?; // execution map key + expected producers set.
        counter.key_clones(&binding.compatibility.execution_owner.id)?;
        counter.owned(&binding.compatibility.execution_owner.id)?; // expected positions set.
    }
    counter.tree::<Id, ()>(snapshot.positions.len(), true)?;
    counter.tree::<Id, ()>(graph.owners().count(), true)?;
    counter.tree::<Id, ()>(snapshot.producers.len(), true)?;
    counter.tree::<Id, ()>(graph.node_ids().count(), true)?;
    for row in &snapshot.positions {
        counter.key_clones(&row.owner)?;
    }
    for row in &snapshot.producers {
        counter.key_clones(&row.node)?;
    }
    counter.tree::<Id, Position>(snapshot.positions.len(), true)?;
    counter.tree::<Id, Option<U64>>(snapshot.producers.len(), true)?;
    counter.tree::<(Id, U64), ()>(snapshot.pending_deliveries.len(), false)?;
    for row in &snapshot.pending_deliveries {
        counter.owned(&row.producer)?;
        counter.owned(&row.payload)?; // Independent fresh content_ref comparison.
    }
    counter.tree::<crucible_node_format::ContentRef, &crate::node_scheduling::SavedPayload>(
        snapshot.payload_objects.len(),
        true,
    )?;
    for row in &snapshot.payload_objects {
        counter.owned(&row.reference)?;
    }
    counter.tree::<Id, ()>(snapshot.used_operations.len(), true)?;
    counter.tree::<Id, ()>(snapshot.reservations.len(), false)?;
    for id in &snapshot.used_operations {
        counter.owned(id)?;
    }
    for row in &snapshot.reservations {
        counter.owned(&row.owner)?;
    }
    for row in &snapshot.input_batches {
        counter.tree::<Id, ()>(2, true)?;
        counter.slots::<crate::node_contract::OwnerIdentity>(
            target
                .owners
                .len()
                .checked_mul(4)
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        counter.owned(&target.owners)?;
        // validate_structure constructs the real delivery Value/canonical bank.
        counter.add(
            NodeRuntime::original_runtime_constructor_serialization_storage_data(
                &row.deliveries,
                counter.maximum,
            )?,
        )?;
        for delivery in &row.deliveries {
            counter.key_clones(&delivery.producer)?;
            counter.key_clones(&delivery.consumer)?;
            counter.owned(&delivery.producer)?; // input_identity comparison.
        }
        for payload in &row.payloads {
            counter.key_clones(&payload.reference)?;
            counter.owned(&payload.reference)?; // Fresh content_ref hash/media.
        }
        counter.owned(&row.inventory)?; // Fresh canonical inventory reference.
    }
    // All bounded_sorted/windows keys are explicit clones. Sum complete key
    // banks conservatively rather than assuming nonoverlap with map validation.
    for row in &snapshot.source_owners {
        counter.key_clones(&row.owner)?;
    }
    for row in &snapshot.positions {
        counter.key_clones(&row.owner)?;
    }
    for row in &snapshot.producers {
        counter.key_clones(&row.node)?;
    }
    for id in &snapshot.used_operations {
        counter.key_clones(id)?;
    }
    for id in &snapshot.used_input_batches {
        counter.key_clones(id)?;
    }
    for row in &snapshot.input_batches {
        counter.key_clones(&row.owner)?;
    }
    for row in &snapshot.reservations {
        counter.key_clones(&row.operation)?;
    }
    for row in &snapshot.pending_deliveries {
        counter.key_clones(&row.producer)?;
        counter.key_clones(&row.consumer)?;
    }
    for row in &snapshot.native_sequences {
        counter.key_clones(&row.endpoint)?;
    }
    for row in &snapshot.payload_objects {
        counter.key_clones(&row.reference)?;
        counter.owned(&row.reference)?; // Fresh content_ref from actual bytes.
    }
    // Original runtime owner reservation validation stores borrowed keys only.
    counter.tree::<&Id, &Id>(runtime.owners.len(), false)?;
    let mut domains = 0usize;
    for owner in &runtime.owners {
        domains = domains
            .checked_add(owner.domains.len())
            .ok_or(RuntimeError::ResourceLimit)?;
    }
    counter.tree::<&Id, &Id>(domains, false)?;
    // saved_permission may clone quantum window/input IDs during comparisons.
    for operation in &runtime.operations {
        counter.owned(&operation.request)?;
    }
    Ok(())
}

fn scheduler_initial_storage(
    graph: &AdmittedGraph,
    target: &ActivationRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    let nodes = graph.node_ids().count();
    let owners = graph.owners().count();
    counter.tree::<Id, Id>(nodes, false)?;
    counter.tree::<Id, Vec<crate::node_contract::OwnerIdentity>>(nodes, false)?;
    counter.tree::<Id, OwnerSchedule>(owners, false)?;
    counter.tree::<Id, OutputBound>(nodes, false)?;
    counter.tree::<Id, Option<U64>>(nodes, false)?;
    counter.tree::<Id, Position>(nodes, true)?;
    // Existing requested-owner readers name empty roots too. These defining
    // zero-entry rows do not infer allocation from an empty std BTreeMap.
    counter.tree::<Endpoint, U64>(0, false)?;
    counter.tree::<Endpoint, ExternalRootPolicy>(0, false)?;
    counter.tree::<Endpoint, Position>(0, true)?;
    for node in graph.node_ids() {
        let binding = graph.binding(node).ok_or(RuntimeError::UnknownNode)?;
        let owner = &binding.compatibility.execution_owner.id;
        let policy = graph
            .operating_policy(node)
            .ok_or(RuntimeError::UnsupportedFacet)?;
        // One key per new map: node_owners/routes/bounds/sequences/closed.
        counter.owned(node)?;
        counter.owned(node)?;
        counter.owned(node)?;
        counter.owned(node)?;
        counter.owned(node)?;
        counter.owned(owner)?; // node_owners value.
        counter.owned(owner)?; // owner schedule key.
        counter.owned(policy)?;
        counter.owned(&target.owners)?; // Actual route is a target subset.
        counter.tree::<Id, ()>(2, true)?; // Source/capture route_ids.
        counter.owned(owner)?;
        counter.owned(&binding.compatibility.capture_owner.id)?;
        let descriptor = graph.descriptor(node).ok_or(RuntimeError::UnknownNode)?;
        for port in &descriptor.ports {
            for lane in &port.lanes {
                if lane.direction == crucible_node_format::Direction::Output {
                    counter.tree::<crucible_node_format::Endpoint, U64>(1, false)?;
                    counter.owned(node)?;
                    counter.owned(&port.id)?;
                    counter.owned(&lane.id)?;
                }
            }
        }
    }
    counter.tree::<Id, RoutingConnection>(graph.world().connections.len(), true)?;
    for connection in &graph.world().connections {
        counter.owned(&connection.id)?;
        let mut actual = crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter::new(
            counter.maximum,
        );
        actual.connection(connection)?;
        actual.connection_policy(
            graph
                .connection_policy(&connection.id)
                .ok_or(RuntimeError::UnsupportedFacet)?,
        )?;
        counter.add(actual.bytes())?;
        // add_path's growable Vec coexists with its old bank during growth.
        counter.slots::<InputPath>(4)?;
        counter.owned(&connection.producer.node_id)?;
    }
    for dependency in &graph.ownership_policy().internal_dependencies {
        counter.slots::<InputPath>(4)?;
        counter.owned(&dependency.producer_node_id)?;
    }
    for endpoint in &graph.coordinator_policy().external_inputs {
        counter.tree::<Endpoint, ExternalRootPolicy>(1, false)?;
        counter.owned(endpoint)?;
        counter.slots::<InputPath>(4)?;
        counter.owned(&endpoint.node_id)?;
        counter.owned(endpoint)?;
    }
    counter.owned(target) // CausalScheduler WorldActivation record clone.
}

fn scheduler_load_storage(
    snapshot: &SchedulingSnapshot,
    target: &ActivationRecord,
    counter: &mut Requested,
) -> Result<(), RuntimeError> {
    counter.tree::<crucible_node_format::EventKey, Delivery>(
        snapshot.pending_deliveries.len(),
        true,
    )?;
    for delivery in &snapshot.pending_deliveries {
        counter.owned(&delivery.consumer)?;
        counter.owned(&delivery.producer)?;
    }
    counter.tree::<Id, ()>(snapshot.used_operations.len(), true)?;
    counter.tree::<Id, ()>(snapshot.used_input_batches.len(), true)?;
    counter.tree::<Endpoint, U64>(snapshot.native_sequences.len(), true)?;
    counter
        .tree::<crucible_node_format::ContentRef, Vec<u8>>(snapshot.payload_objects.len(), true)?;
    for saved in &snapshot.producers {
        counter.owned(&saved.node)?; // Existing bound-map insertion key.
        counter.owned(&saved.node)?; // Existing sequence-map insertion key.
    }
    counter.tree::<Id, Reservation>(snapshot.reservations.len(), false)?;
    for saved in &snapshot.reservations {
        counter.owned(&saved.operation)?; // OwnerSchedule.reserved clone.
        counter.owned(&saved.permission)?; // saved_request clones quantum fields.
    }
    counter.tree::<Id, InputBatchState>(snapshot.input_batches.len(), false)?;
    for saved in &snapshot.input_batches {
        counter.owned(target)?;
        // Source owners move out with the snapshot but load_snapshot replaces
        // that route with a fresh node_routes clone beneath current authority.
        counter.owned(&target.owners)?;
        if let Some(ack) = &saved.acknowledgement {
            fresh_ack_backing(ack, target, counter)?;
        }
    }
    Ok(())
}

impl PreparedSchedulingRestore {
    pub(crate) fn original_lineage_construction_storage_data(
        graph: &AdmittedGraph,
        record: &OriginalLineageRuntimeRecord,
        snapshot: &SchedulingSnapshot,
        target: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        Self::original_lineage_publication_projection_data(record, snapshot, target)?;
        let mut counter = Requested { bytes: 0, maximum };
        counter.add(size_of::<Self>())?;
        counter.add(size_of::<CausalScheduler>())?;
        // HostSchedulingContinuation copies this actual snapshot once before
        // prepare_original_lineage; load_snapshot then moves its child owners.
        counter.owned(snapshot)?;
        counter.owned(target)?;
        let count = record
            .inputs
            .iter()
            .filter(|input| input.acknowledgement.is_some())
            .count();
        counter.slots::<crate::node_scheduling::NativeInputAcknowledgement>(count)?;
        for input in &record.inputs {
            if let Some(ack) = &input.acknowledgement {
                fresh_ack_backing(ack, target, &mut counter)?;
                // prepare_original_lineage's temporary filtered owner Vec.
                counter.slots::<crate::node_contract::OwnerIdentity>(
                    target
                        .owners
                        .len()
                        .checked_mul(4)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )?;
                counter.owned(&target.owners)?;
            }
        }
        validation_storage(graph, record, snapshot, target, &mut counter)?;
        scheduler_initial_storage(graph, target, &mut counter)?;
        scheduler_load_storage(snapshot, target, &mut counter)?;
        counter.add(error_formatter_storage_data()?)?;
        Ok(counter.bytes)
    }
}

// No arbitrary Display implementation is invoked by the data quote. These are
// the closed scheduler variants and contract leaf failures reachable from
// original schema1 prepare/activate/load. Event parse errors are mapped to the
// nonformatting InvalidReceipt path outside this scheduler. Delivery's concrete
// serializer has only bounded Id/ContentRef/Position/integer fields; it contains
// no custom erased serializer, floating point or unsupported map key.
fn error_formatter_storage_data() -> Result<usize, RuntimeError> {
    const LEAVES: &[&str] = &[
        "foreign or stale world activation",
        "unknown scheduling node",
        "unsupported scheduling mode or boundary representation",
        "authenticated native scheduling or input evidence is unavailable",
        "no safe representable execution interval",
        "execution owner has an unresolved grant",
        "operation identity already used",
        "invalid scheduling receipt; original reservation retained",
        "retained outputs lack authenticated causal coordinates",
        "causal event regressed behind its parent or activated input cut",
        "invalid publication coordinate",
        "same-time closure did not converge within its admitted bound",
        "producer public sequence exhausted",
        "invalid or incomplete scheduling snapshot",
        "snapshot retains unresolved native operation custody",
        "coordinator continuation capacity exhausted",
        "contract arithmetic overflow",
        "invalid id: expected 1–128 bounded ASCII identifier bytes",
        "invalid algorithm: unsupported hash algorithm",
        "invalid domain: expected 1–128 ASCII bytes",
        "invalid digest: expected 64 lowercase hexadecimal characters",
        "invalid hash.domain: content must use cnp.blob.v1",
        "invalid media_type: expected 1–128 printable ASCII bytes",
        "invalid grid: require positive quantum and phase < quantum",
        "invalid instant: before grid phase",
        "invalid microstep: same-time closure limit exceeded",
    ];
    let mut largest = "input closure is blocked by producer "
        .len()
        .checked_add(128)
        .ok_or(RuntimeError::ResourceLimit)?;
    let mut reason = 0usize;
    for leaf in LEAVES {
        largest = largest.max(
            "invalid scheduling contract: "
                .len()
                .checked_add(leaf.len())
                .ok_or(RuntimeError::ResourceLimit)?,
        );
        reason = reason.max(leaf.len());
    }
    // Existing ContractError retains its original literal reason while
    // SchedulingError::to_string grows an independent output String.
    largest
        .checked_mul(4)
        .and_then(|n| n.checked_add(256))
        .and_then(|n| n.checked_add(reason))
        .ok_or(RuntimeError::ResourceLimit)
}

// These are actual logical collection/return views, not padding for compiler
// frames. Iterator wrappers have their base cursor plus named captured loans;
// collect/sort heap storage is independently charged by tree(...,true).
struct ValidationViews<'a> {
    graph_owners: BTreeSet<Id>,
    source_owners: BTreeSet<Id>,
    target_owners: BTreeSet<Id>,
    execution_owners: BTreeMap<Id, Id>,
    owner_contracts: BTreeMap<Id, (QuantumGrid, ExecutionPolicy)>,
    positions_actual: BTreeSet<Id>,
    positions_expected: BTreeSet<Id>,
    producers_actual: BTreeSet<Id>,
    producers_expected: BTreeSet<Id>,
    positions: BTreeMap<Id, Position>,
    sequences: BTreeMap<Id, Option<U64>>,
    pending_sequences: BTreeSet<(Id, U64)>,
    payloads: BTreeMap<crucible_node_format::ContentRef, &'a crate::node_scheduling::SavedPayload>,
    used: BTreeSet<Id>,
    reserved: BTreeSet<Id>,
    batch_routes: BTreeSet<Id>,
    batch_owners: Vec<crate::node_contract::OwnerIdentity>,
    runtime_owners: BTreeMap<&'a Id, &'a Id>,
    runtime_domains: BTreeMap<&'a Id, &'a Id>,
    record_inputs: std::slice::Iter<'a, crate::node_contract::OriginalLineageInputRecord>,
    snapshot_inputs: std::slice::Iter<'a, SavedInputBatch>,
    deliveries: std::slice::Iter<'a, Delivery>,
    reserved_rows: std::slice::Iter<'a, SavedReservation>,
    target_loan: &'a ActivationRecord,
    record_loan: &'a OriginalLineageRuntimeRecord,
    source_loan: &'a SchedulingSnapshot,
}

impl PreparedSchedulingRestore {
    pub(crate) fn original_lineage_construction_counter_scratch_data() -> Result<usize, RuntimeError>
    {
        let alignment = align_of::<(crucible_node_format::EventKey, Delivery)>()
            .max(align_of::<(Id, RoutingConnection)>())
            .max(align_of::<(Id, InputBatchState)>());
        let width = size_of::<(crucible_node_format::EventKey, Delivery)>()
            .max(size_of::<(Id, RoutingConnection)>())
            .max(size_of::<(Id, InputBatchState)>())
            .max(size_of::<(Id, OwnerSchedule)>());
        let sort = ((4096 + alignment - 1) & !(alignment - 1))
            .checked_add(width)
            .and_then(|n| n.checked_add(3 * size_of::<usize>()))
            .and_then(|n| n.checked_add(size_of::<[usize; 66]>()))
            .and_then(|n| n.checked_add(size_of::<[u8; 66]>()))
            .ok_or(RuntimeError::ResourceLimit)?;
        let rows = [
            Self::original_retained_installation_duplicate_counter_scratch_data(),
            super::validation::input_custody::counter_scratch_data(),
            size_of::<Requested>(),
            size_of::<ValidationViews<'_>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<OriginalSchedulingRestorationPublicationProjection<'_>>(),
            size_of::<Result<OriginalSchedulingRestorationPublicationProjection<'_>, RuntimeError>>(
            ),
            size_of::<FreshAcknowledgements<'_>>(),
            size_of::<FreshAcknowledgement<'_>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<(), SchedulingError>>(),
            size_of::<Result<Self, SchedulingError>>(),
            size_of::<Result<CausalScheduler, SchedulingError>>(),
            size_of::<Result<crucible_node_format::ContentRef, crucible_node_format::ContractError>>(
            ),
            size_of::<Result<serde_json::Value, serde_json::Error>>(),
            size_of::<Result<Vec<u8>, crucible_node_format::ContractError>>(),
            size_of::<crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter>(),
            size_of::<blake3::Hasher>(),
            size_of::<[u8; 64]>(),
            size_of::<[u8; 20]>(),
            size_of::<
                std::collections::btree_map::Keys<'static, Id, crucible_node_format::NodeBinding>,
            >(),
            size_of::<
                std::collections::btree_map::Values<
                    'static,
                    Id,
                    crucible_node_format::OwnerBinding,
                >,
            >(),
            size_of::<std::slice::Windows<'static, Id>>(),
            2 * size_of::<crucible_node_format::EventKey>(),
            2 * size_of::<Endpoint>(),
            2 * size_of::<crucible_node_format::ContentRef>(),
            2 * size_of::<Id>(),
            size_of::<Vec<(crucible_node_format::EventKey, Delivery)>>(),
            size_of::<Vec<(Id, RoutingConnection)>>(),
            size_of::<Vec<Id>>(),
            size_of::<Vec<(Id, Position)>>(),
            size_of::<Vec<(Id, Option<U64>)>>(),
            size_of::<Vec<(Endpoint, U64)>>(),
            size_of::<Vec<(crucible_node_format::ContentRef, Vec<u8>)>>(),
            NodeRuntime::capture_serialization_counter_scratch_data(),
            sort,
        ];
        // This getter's own fixed row array and its slice cursor are declared
        // logical views too; no compiler frame or unrelated padding is inferred.
        let fixed_views = std::mem::size_of_val(&rows)
            .checked_add(size_of::<std::slice::Iter<'static, usize>>())
            .ok_or(RuntimeError::ResourceLimit)?;
        rows.iter().try_fold(fixed_views, |sum, bytes| {
            sum.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_contract::{OriginalLineageInputRecord, OwnerIdentity, SavedRuntimeActivation};
    use crucible_node_format::{HashRef, Phase};

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn inert_data() -> (
        OriginalLineageRuntimeRecord,
        SchedulingSnapshot,
        ActivationRecord,
    ) {
        let boundary = Position::new(10.into(), 0.into(), Phase::BoundaryControl);
        let world = HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.world-binding.v1".into(),
            digest: "1".repeat(64),
        };
        let target = ActivationRecord {
            generation: 2.into(),
            activation_id: id("target"),
            world_binding_hash: world.clone(),
            boundary,
            owners: (0..4)
                .map(|n| OwnerIdentity {
                    owner: id(&format!("owner-{n}")),
                    incarnation: id(&format!("fresh-{n}")),
                    generation: 2.into(),
                })
                .collect(),
        };
        let inventory =
            crucible_node_format::canonical::content_ref(b"[]", "application/json").unwrap();
        let ack = crate::node_scheduling::NativeInputAcknowledgement {
            stage_operation: id("stage"),
            batch: id("batch"),
            node: id("node"),
            owners: target.owners.clone(),
            inventory: inventory.clone(),
            cutoff: boundary,
            proof_ref: crucible_node_format::canonical::content_ref(b"proof", "application/json")
                .unwrap(),
        };
        let input = OriginalLineageInputRecord {
            node: ack.node.clone(),
            stage_operation: ack.stage_operation.clone(),
            batch: ack.batch.clone(),
            owners: ack.owners.clone(),
            cutoff: boundary,
            inventory: inventory.clone(),
            deliveries: vec![],
            payloads: vec![],
            provenance: None,
            lineage: None,
            acknowledgement: Some(ack.clone()),
            failure: None,
            committed: true,
            coordinator_committed: true,
        };
        let record = OriginalLineageRuntimeRecord {
            schema_version: 7,
            source_activation: SavedRuntimeActivation::from(&target),
            capture_cut: boundary,
            capture_ordinal: 3.into(),
            owners: vec![],
            operations: vec![],
            inputs: vec![input],
        };
        let snapshot = SchedulingSnapshot {
            schema_version: 1,
            original_epochs: None,
            ordering_profile: "superdense-v1".into(),
            world_binding_hash: world,
            source_activation_id: id("source"),
            source_generation: 1.into(),
            source_boundary: boundary,
            capture_cut: boundary,
            capture_ordinal: 3.into(),
            source_owners: vec![],
            maximum_microsteps: 10.into(),
            positions: vec![],
            producers: vec![],
            native_sequences: vec![],
            external_closed_prefixes: vec![],
            payload_objects: vec![],
            pending_deliveries: vec![],
            used_operations: vec![ack.stage_operation.clone()],
            reservations: vec![],
            input_batches: vec![SavedInputBatch {
                owner: id("owner-0"),
                node: ack.node.clone(),
                stage_operation: ack.stage_operation.clone(),
                batch: ack.batch.clone(),
                owners: ack.owners.clone(),
                cutoff: boundary,
                inventory,
                deliveries: vec![],
                payloads: vec![],
                acknowledgement: Some(ack),
                custody_edition: Some(1),
                consumer_committed: true,
                activated_by: Some(id("source")),
                consumed: vec![],
            }],
            used_input_batches: vec![id("batch")],
        };
        (record, snapshot, target)
    }

    // Directly constructing a paused DTO here grants no WorldActivation or
    // native context. The test compares the real old publication serializer.
    #[test]
    fn paused_publication_projection_dominates_real_serializer_and_fresh_ack_backing() {
        let (record, snapshot, target) = inert_data();
        let mut fresh = record.inputs[0].acknowledgement.clone().unwrap();
        fresh.proof_ref.hash.digest = "f".repeat(64);
        let prepared = PreparedSchedulingRestore {
            target: target.clone(),
            snapshot: snapshot.clone(),
            input_acknowledgements: vec![fresh.clone()],
            epochs: None,
        };
        let projection = PreparedSchedulingRestore::original_lineage_publication_projection_data(
            &record, &snapshot, &target,
        )
        .unwrap();
        let projected = crucible_node_format::canonical::canonical_json(
            &serde_json::to_value(&projection).unwrap(),
        )
        .unwrap();
        let actual = crucible_node_format::canonical::canonical_json(
            &serde_json::to_value(prepared.original_publication_data()).unwrap(),
        )
        .unwrap();
        assert!(projected.len() >= actual.len());
        let projected_value = serde_json::to_value(&projection).unwrap();
        let actual_value = serde_json::to_value(prepared.original_publication_data()).unwrap();
        assert_eq!(projected_value[0], actual_value[0]);
        assert_eq!(projected_value[1], actual_value[1]);
        assert_eq!(
            projected_value[2][0]["inventory"],
            actual_value[2][0]["inventory"]
        );
        assert_eq!(projected_value[3], actual_value[3]);
        let mut bound = Requested {
            bytes: 0,
            maximum: usize::MAX,
        };
        fresh_ack_backing(
            record.inputs[0].acknowledgement.as_ref().unwrap(),
            &target,
            &mut bound,
        )
        .unwrap();
        assert!(bound.bytes >= fresh.owned_storage().unwrap());
        let mut short = Requested {
            bytes: 0,
            maximum: bound.bytes - 1,
        };
        assert!(matches!(
            fresh_ack_backing(
                record.inputs[0].acknowledgement.as_ref().unwrap(),
                &target,
                &mut short
            ),
            Err(RuntimeError::ResourceLimit)
        ));
    }

    #[test]
    fn paused_publication_projection_refuses_missing_correspondence_and_combined_editions() {
        let (mut record, mut snapshot, target) = inert_data();
        record.inputs.clear();
        assert!(matches!(
            PreparedSchedulingRestore::original_lineage_publication_projection_data(
                &record, &snapshot, &target
            ),
            Err(RuntimeError::UnsupportedFacet)
        ));
        snapshot.original_epochs = Some(vec![]);
        assert!(matches!(
            PreparedSchedulingRestore::original_lineage_publication_projection_data(
                &record, &snapshot, &target
            ),
            Err(RuntimeError::UnsupportedFacet)
        ));
        assert!(matches!(
            Requested {
                bytes: usize::MAX,
                maximum: usize::MAX
            }
            .slots::<Delivery>(1),
            Err(RuntimeError::ResourceLimit)
        ));
    }

    #[test]
    fn common_scheduler_error_formatter_bound_covers_real_direct_failures() {
        use crucible_node_format::{ContractError, Validate};
        let (_, _, target) = inert_data();
        let mut errors = vec![
            SchedulingError::ForeignActivation,
            SchedulingError::UnknownNode,
            SchedulingError::UnsupportedMode,
            SchedulingError::MissingObservation,
            SchedulingError::InputBlocked(Id::new("p".repeat(128)).unwrap()),
            SchedulingError::NoSafeProgress,
            SchedulingError::OwnerBusy,
            SchedulingError::DuplicateOperation,
            SchedulingError::InvalidReceipt,
            SchedulingError::MissingOutputCoordinates,
            SchedulingError::CausalRegression,
            SchedulingError::InvalidPublication,
            SchedulingError::SameTimeNonconvergence,
            SchedulingError::SequenceExhausted,
            SchedulingError::InvalidSnapshot,
            SchedulingError::UnresolvedCustody,
            SchedulingError::CapacityExceeded,
            SchedulingError::Contract(ContractError::Overflow),
            SchedulingError::Contract(QuantumGrid::new(0.into(), 0.into()).unwrap_err()),
        ];
        let mut invalid = target.world_binding_hash;
        invalid.algorithm = "unsupported".into();
        errors.push(SchedulingError::Contract(invalid.validate().unwrap_err()));
        invalid.algorithm = "blake3-256".into();
        invalid.domain.clear();
        errors.push(SchedulingError::Contract(invalid.validate().unwrap_err()));
        invalid.domain = "cnp.blob.v1".into();
        invalid.digest.clear();
        errors.push(SchedulingError::Contract(invalid.validate().unwrap_err()));
        let bound = error_formatter_storage_data().unwrap();
        for error in errors {
            let retained_reason = match &error {
                SchedulingError::Contract(ContractError::Invalid { reason, .. }) => {
                    reason.capacity()
                }
                _ => 0,
            };
            let formatted = error.to_string();
            assert!(bound >= retained_reason + formatted.capacity());
        }
    }

    #[test]
    fn actual_paused_owner_census_observes_spare_backing_and_refuses_one_short() {
        let (record, mut snapshot, target) = inert_data();
        snapshot.ordering_profile.reserve(4096);
        let mut acknowledgements = Vec::with_capacity(32);
        acknowledgements.push(record.inputs[0].acknowledgement.clone().unwrap());
        let prepared = PreparedSchedulingRestore {
            target,
            snapshot,
            input_acknowledgements: acknowledgements,
            epochs: None,
        };
        let expected = size_of::<PreparedSchedulingRestore>()
            + prepared.target.owned_storage().unwrap()
            + prepared.snapshot.owned_storage().unwrap()
            + prepared.input_acknowledgements.owned_storage().unwrap();
        assert!(
            expected >= 4096 + 32 * size_of::<crate::node_scheduling::NativeInputAcknowledgement>()
        );
        assert_eq!(
            prepared
                .original_retained_requested_storage_precredit_data(expected)
                .unwrap(),
            expected
        );
        assert!(matches!(
            prepared.original_retained_requested_storage_precredit_data(expected - 1),
            Err(RuntimeError::ResourceLimit)
        ));
        let mut unsupported = prepared;
        unsupported.snapshot.original_epochs = Some(vec![]);
        assert!(matches!(
            unsupported.original_retained_requested_storage_precredit_data(usize::MAX),
            Err(RuntimeError::UnsupportedFacet)
        ));
    }

    // Paused DATA alone grants no activation or runtime/native permission.
    #[test]
    fn retained_installation_duplicate_keeps_original_banks_and_refuses_short_credit() {
        let (record, mut snapshot, target) = inert_data();
        snapshot.ordering_profile.reserve(4096);
        let acknowledgements = vec![record.inputs[0].acknowledgement.clone().unwrap()];
        let prepared = PreparedSchedulingRestore {
            target,
            snapshot,
            input_acknowledgements: acknowledgements,
            epochs: None,
        };
        let actual = prepared
            .original_retained_requested_storage_precredit_data(usize::MAX)
            .unwrap();
        let before = crucible_node_format::canonical::canonical_json(
            &serde_json::to_value(prepared.original_publication_data()).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            prepared.duplicate_original_retained_for_installation_data(actual - 1),
            Err(RuntimeError::ResourceLimit)
        ));
        assert_eq!(
            crucible_node_format::canonical::canonical_json(
                &serde_json::to_value(prepared.original_publication_data()).unwrap()
            )
            .unwrap(),
            before
        );
        let mut duplicate = prepared
            .duplicate_original_retained_for_installation_data(actual)
            .unwrap();
        assert_eq!(
            crucible_node_format::canonical::canonical_json(
                &serde_json::to_value(duplicate.original_publication_data()).unwrap()
            )
            .unwrap(),
            before
        );
        assert_ne!(
            prepared.snapshot.ordering_profile.as_ptr(),
            duplicate.snapshot.ordering_profile.as_ptr()
        );
        assert_ne!(
            prepared.input_acknowledgements.as_ptr(),
            duplicate.input_acknowledgements.as_ptr()
        );
        assert!(
            duplicate
                .original_retained_requested_storage_precredit_data(actual)
                .is_ok()
        );

        duplicate.snapshot.ordering_profile.push_str("-independent");
        drop(duplicate); // Models a consuming validation failure's dropped DATA.
        assert_eq!(
            crucible_node_format::canonical::canonical_json(
                &serde_json::to_value(prepared.original_publication_data()).unwrap()
            )
            .unwrap(),
            before
        );
        assert_eq!(
            prepared
                .original_retained_requested_storage_precredit_data(actual)
                .unwrap(),
            actual
        );
        let mut unsupported = prepared;
        unsupported.snapshot.original_epochs = Some(vec![]);
        assert!(matches!(
            unsupported.duplicate_original_retained_for_installation_data(usize::MAX),
            Err(RuntimeError::UnsupportedFacet)
        ));
    }

    #[test]
    fn prospective_paused_duplicate_funds_actual_clone_and_refuses_one_short() {
        let (record, snapshot, target) = inert_data();
        let bound = PreparedSchedulingRestore::original_lineage_retained_installation_duplicate_storage_data(
            &record, &snapshot, &target, usize::MAX).unwrap();
        let mut fresh = record.inputs[0].acknowledgement.clone().unwrap();
        fresh.proof_ref.hash.digest = "f".repeat(64);
        let prepared = PreparedSchedulingRestore {
            target,
            snapshot,
            input_acknowledgements: vec![fresh],
            epochs: None,
        };

        let duplicate = prepared
            .duplicate_original_retained_for_installation_data(bound)
            .unwrap();
        assert!(
            duplicate
                .original_retained_requested_storage_precredit_data(bound)
                .is_ok()
        );
        assert_eq!(PreparedSchedulingRestore::original_lineage_retained_installation_duplicate_storage_data(
            &record, &prepared.snapshot, &prepared.target, bound).unwrap(), bound);
        assert!(matches!(PreparedSchedulingRestore::original_lineage_retained_installation_duplicate_storage_data(
            &record, &prepared.snapshot, &prepared.target, bound - 1), Err(RuntimeError::ResourceLimit)));
        assert!(
            PreparedSchedulingRestore::original_retained_installation_duplicate_counter_scratch_data(
            ) >= size_of::<Result<PreparedSchedulingRestore, RuntimeError>>()
        );
    }
}
