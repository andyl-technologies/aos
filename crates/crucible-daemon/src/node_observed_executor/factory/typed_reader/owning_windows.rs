//! Validates original typed checksum windows and pre-Stage producer associations.

use std::io::{self, Write};

use crucible::node_adapters::cnp::OriginalRuntimeLineage;
use crucible::node_contract::{
    InputProvenanceClosure, OriginalInputLineage, OriginalPublicationOrigin,
};
use crucible::node_scheduling::RuntimeInputBatch;
use crucible_node_contract::{ContentRef, Event, U64, canonical};
use crucible_node_provider::ProviderError;
use serde::Serialize;

use super::{OriginalTypedPolicy, invalid};

#[derive(Serialize, PartialEq)]
pub(super) struct WindowSeal {
    quantum: U64,
    receipt: ContentRef,
    checksum: U64,
    published: ContentRef,
    event: Event,
    origin: OriginalPublicationOrigin,
}

#[derive(Serialize)]
struct BorrowedWindowSeal<'a> {
    quantum: U64,
    receipt: &'a ContentRef,
    checksum: U64,
    published: &'a ContentRef,
    event: &'a Event,
    origin: BorrowedOrigin<'a>,
}

#[derive(Serialize)]
struct BorrowedOrigin<'a> {
    owner_binding_hash: &'a crucible_node_contract::HashRef,
    execution_owner_id: &'a crucible_node_contract::Id,
    session_id: &'a crucible_node_contract::Id,
    world_binding_hash: &'a crucible_node_contract::HashRef,
    activation_id: &'a crucible_node_contract::Id,
    world_generation: U64,
    incarnation_id: &'a crucible_node_contract::Id,
    owner_generation: U64,
    operation_id: &'a crucible_node_contract::Id,
    grant_id: &'a crucible_node_contract::Id,
    observation_batch: &'a ContentRef,
    stop_receipt: &'a ContentRef,
    measurement: &'a ContentRef,
}

struct Credit(usize, usize);

impl Write for Credit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|count| *count <= self.1)
            .ok_or_else(|| io::Error::other("typed original metadata credit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn count(value: &impl Serialize, maximum: usize) -> Result<(), ProviderError> {
    serde_json::to_writer(Credit(0, maximum), value).map_err(|_| invalid())
}

fn object(value: &impl Serialize) -> Result<ContentRef, ProviderError> {
    count(value, 65536)?;
    let value = serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    Ok(canonical::content_ref(&bytes, "application/json")?)
}

fn retain_seal(
    borrowed: &BorrowedWindowSeal<'_>,
    maximum: usize,
) -> Result<WindowSeal, ProviderError> {
    count(borrowed, maximum)?;
    #[cfg(test)]
    COPIES.with(|copies| copies.set(copies.get() + 1));
    let origin = &borrowed.origin;
    Ok(WindowSeal {
        quantum: borrowed.quantum,
        receipt: borrowed.receipt.clone(),
        checksum: borrowed.checksum,
        published: borrowed.published.clone(),
        event: borrowed.event.clone(),
        origin: OriginalPublicationOrigin {
            owner_binding_hash: origin.owner_binding_hash.clone(),
            execution_owner_id: origin.execution_owner_id.clone(),
            session_id: origin.session_id.clone(),
            world_binding_hash: origin.world_binding_hash.clone(),
            activation_id: origin.activation_id.clone(),
            world_generation: origin.world_generation,
            incarnation_id: origin.incarnation_id.clone(),
            owner_generation: origin.owner_generation,
            operation_id: origin.operation_id.clone(),
            grant_id: origin.grant_id.clone(),
            observation_batch: origin.observation_batch.clone(),
            stop_receipt: origin.stop_receipt.clone(),
            measurement: origin.measurement.clone(),
        },
    })
}

#[cfg(test)]
std::thread_local! {
    static COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn authenticate_window(
    policy: &OriginalTypedPolicy,
    original: &OriginalRuntimeLineage<'_>,
) -> Result<(), ProviderError> {
    let source = original.source();
    let enrolled = policy
        .source
        .enrollment
        .try_borrow()
        .map_err(|_| invalid())?;
    let enrolled = enrolled.as_ref().ok_or_else(invalid)?;
    let graph = policy.source.graph.try_borrow().map_err(|_| invalid())?;
    if graph.as_ref() != Some(&source.stop().world_binding_hash)
        || source.native_pid().get() != u64::from(enrolled.native)
        || source.native_executable()
            != policy
                .source
                .package
                .artifact_content("device")
                .map_err(|_| invalid())?
        || original.operation().token().route().node != policy.source.profile.descriptor.id
    {
        return Err(invalid());
    }

    let stage = source.native_stage();
    let receipt = source.native_receipt();
    stage.validate()?;
    if receipt.stage != stage.identity()?
        || receipt.grant != stage.grant
        || receipt.consumed.len() != stage.entries.len()
        || !receipt.application_parked
        || source.controlled_receipt().grant != stage.grant
        || source.controlled_receipt().output != receipt.output
    {
        return Err(invalid());
    }
    let mut checksum = receipt.checksum_before.get();
    for (entry, consumed) in stage.entries.iter().zip(&receipt.consumed) {
        let start = usize::try_from(entry.byte_start.get()).map_err(|_| invalid())?;
        let end = usize::try_from(entry.byte_end.get()).map_err(|_| invalid())?;
        let bytes = stage.input.get(start..end).ok_or_else(invalid)?;
        let payload = original
            .input()
            .payloads()
            .iter()
            .find(|payload| payload.reference == entry.payload)
            .ok_or_else(invalid)?;
        if payload.bytes != bytes
            || consumed.event_index != entry.event_index
            || consumed.byte_start != entry.byte_start
            || consumed.byte_end != entry.byte_end
        {
            return Err(invalid());
        }
        for byte in bytes {
            checksum = checksum.wrapping_mul(257).wrapping_add(u64::from(*byte));
        }
        if checksum != consumed.checksum_after.get() {
            return Err(invalid());
        }
    }
    if receipt.output.checksum.get() != checksum
        || receipt.output.bytes_processed.get() != stage.input.len() as u64
    {
        return Err(invalid());
    }
    let [event] = source.observation().events.as_slice() else {
        return Err(invalid());
    };
    let stop = source.stop();
    let receipt_reference = receipt.identity()?;
    let published = object(event)?;
    let stop_reference = object(stop)?;
    let grant = stop.grant_id.as_ref().ok_or_else(invalid)?;
    let borrowed = BorrowedWindowSeal {
        quantum: stage.grant.quantum,
        receipt: &receipt_reference,
        checksum: U64::new(checksum),
        published: &published,
        event,
        origin: BorrowedOrigin {
            owner_binding_hash: &stop.owner_binding_hash,
            execution_owner_id: &stop.execution_owner_id,
            session_id: &stop.session_id,
            world_binding_hash: &stop.world_binding_hash,
            activation_id: &stop.activation_id,
            world_generation: stop.world_generation,
            incarnation_id: &stop.incarnation_id,
            owner_generation: stop.owner_generation,
            operation_id: &stop.operation_id,
            grant_id: grant,
            observation_batch: &stop.observation_batch,
            stop_receipt: &stop_reference,
            measurement: source.measurement_reference(),
        },
    };
    let seal = retain_seal(&borrowed, 65536)?;
    let mut retained = policy
        .source
        .windows
        .try_borrow_mut()
        .map_err(|_| invalid())?;
    if let super::HostAuthority::Fixture {
        policy: fixture,
        plan,
    } = policy.authority.as_ref()
    {
        // Installed oracle refusal cannot leave a new approved producer seal.
        // The callback runs without a mutable history borrow held across it.
        drop(retained);
        fixture.authenticate_window(
            plan,
            &policy.source.package,
            &policy.source.profile,
            original,
        )?;
        retained = policy
            .source
            .windows
            .try_borrow_mut()
            .map_err(|_| invalid())?;
    }
    if let Some(old) = retained.iter().find(|old| old.quantum == seal.quantum) {
        return if old == &seal { Ok(()) } else { Err(invalid()) };
    }
    if retained.len() >= policy.source.maximum_windows
        || stage.grant.quantum.get() != retained.len() as u64
    {
        return Err(invalid());
    }
    if let Some(previous) = retained.last() {
        if receipt.previous_closed.as_ref() != Some(&previous.receipt)
            || receipt.checksum_before != previous.checksum
            || source.preceding_public_acknowledgement().is_none()
        {
            return Err(invalid());
        }
    } else if receipt.previous_closed.is_some()
        || receipt.checksum_before.get() != 0
        || source.preceding_public_acknowledgement().is_some()
    {
        return Err(invalid());
    }
    // The opaque source already checks every exact predecessor control/body.
    // A terminal Complete remains held custody; this seal does not label its
    // current output ACKed or replace the later authentic retirement receipt.
    retained.push(seal);
    Ok(())
}

pub(super) fn authenticate_inputs(
    policy: &OriginalTypedPolicy,
    original: &RuntimeInputBatch,
    provenance: &InputProvenanceClosure,
    lineage: &OriginalInputLineage,
) -> Result<(), ProviderError> {
    let source = lineage.original();
    let graph = policy.source.graph.try_borrow().map_err(|_| invalid())?;
    if graph.as_ref() != Some(&original.activation().record().world_binding_hash)
        || original.node() != &policy.source.profile.descriptor.id
        || !source.activation().same_authority(original.activation())
        || source.node() != original.node()
        || source.owners() != original.owners()
        || source.batch() != original.batch()
        || source.cutoff() != original.cutoff()
        || source.stage_operation() != original.stage_operation()
        || source.inventory() != original.inventory()
        || source.deliveries() != original.deliveries()
        || source.payloads() != original.payloads()
        || provenance.version() != 1
        || !provenance
            .activation()
            .same_authority(original.activation())
        || provenance.node() != original.node()
        || provenance.stage_operation() != original.stage_operation()
        || provenance.batch() != original.batch()
        || provenance.inventory() != original.inventory()
        || lineage.publications().len() != original.deliveries().len()
    {
        return Err(invalid());
    }
    for root in provenance.roots() {
        let mut bodies = provenance
            .objects()
            .iter()
            .filter(|object| &object.reference == root);
        let body = bodies.next().ok_or_else(invalid)?;
        if bodies.next().is_some() {
            return Err(invalid());
        }
        root.verify(&body.bytes)?;
    }
    for body in provenance.objects() {
        body.reference.verify(&body.bytes)?;
    }
    let prepared = policy.sources.try_borrow().map_err(|_| invalid())?;
    for (delivery, claim) in original.deliveries().iter().zip(lineage.publications()) {
        let mut candidates = prepared
            .iter()
            .filter(|candidate| candidate.profile.descriptor.id == delivery.producer);
        let producer = candidates.next().ok_or_else(invalid)?;
        if candidates.next().is_some() {
            return Err(invalid());
        }
        let enrolled = producer.enrollment.try_borrow().map_err(|_| invalid())?;
        let enrolled = enrolled.as_ref().ok_or_else(invalid)?;
        super::authenticate_acceptance(policy.authority.as_ref(), producer, &enrolled.realization)?;
        if super::kernel::current(
            &producer.package,
            enrolled.provider,
            enrolled.native,
            &producer.resources,
            &enrolled.kernel.ready,
        )? != enrolled.kernel
        {
            return Err(invalid());
        }
        let seals = producer.windows.try_borrow().map_err(|_| invalid())?;
        let mut seals = seals.iter().filter(|seal| {
            seal.published == claim.published
                && seal.origin.operation_id == claim.origin.operation_id
        });
        let seal = seals.next().ok_or_else(invalid)?;
        if seals.next().is_some()
            || seal.event != claim.event
            || seal.origin != claim.origin
            || claim.event.id != delivery.publication_id
            || claim.event.payload != delivery.payload
            || claim.event.source_sequence != delivery.native_sequence
            || claim.origin.measurement != delivery.provenance_ref
        {
            return Err(invalid());
        }
        // Rows/bodies are runtime-issued original associations; no foreign JSON
        // leaf inference or coordinate-derived producer identity is permitted.
        for object in &claim.objects {
            object.reference.verify(&object.bytes)?;
        }
    }
    Ok(())
}

#[cfg(test)]
// Inert complete-envelope controls intentionally fail on copies before credit.
#[path = "owning_credit_tests.rs"]
mod credit_tests;
