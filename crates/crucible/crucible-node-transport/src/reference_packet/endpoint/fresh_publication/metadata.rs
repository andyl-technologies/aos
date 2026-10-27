//! Observes every independently retained partial Fresh publication owner.
//!
//! The enclosing attempt authenticates its raw origin and startup association
//! before this closed walk. Typed primitive byte banks record actual capacity
//! and length once; literal contents and full proof/hash checks remain separate.

use super::*;
use crate::retained_metadata::MetadataObserver;

impl NativeFreshReportPublication {
    pub(in crate::reference_packet::endpoint) fn observe_retained_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            schema,
            data,
            proof,
            report,
            raw,
            reference,
            inventory_raw,
            inventory_hash,
            result,
            receipt,
            reply,
            completed_response,
            completed_record,
        } = self;
        observer.observe(schema)?;
        observer.observe(&data.is_some())?;
        if let Some(data) = data {
            observe_data(data, observer)?;
        }
        observer.observe(&proof.is_some())?;
        if let Some(proof) = proof {
            observe_proof(proof, observer)?;
        }
        observer.observe(&report.is_some())?;
        if let Some(report) = report {
            let PacketNativeFreshRestoreAllocationReport {
                schema,
                data,
                proof,
            } = report;
            observer.observe(schema)?;
            observe_data(data, observer)?;
            observe_proof(proof, observer)?;
        }
        observe_bytes(raw, observer)?;
        observer.observe(reference)?;
        observe_bytes(inventory_raw, observer)?;
        observer.observe(inventory_hash)?;
        observer.observe(&result.is_some())?;
        if let Some(result) = result {
            let ObserveResult {
                observations,
                next_sequence,
                complete,
                inventory_hash,
            } = result;
            observer.observe(observations)?;
            observer.observe(next_sequence)?;
            observer.observe(complete)?;
            observer.observe(inventory_hash)?;
        }
        observer.observe(&receipt.is_some())?;
        if let Some(receipt) = receipt {
            let PacketNativeFreshRestoreAllocationReceipt { schema, allocation } = receipt;
            observer.observe(schema)?;
            observer.observe(allocation)?;
        }
        observer.observe(&reply.is_some())?;
        if let Some(reply) = reply {
            let super::super::super::control::PacketControlReply { body, evidence } = reply;
            observer.observe(body)?;
            observer.vector::<(ContentRef, Vec<u8>)>(evidence.capacity())?;
            for (reference, bytes) in evidence {
                observer.observe(reference)?;
                observe_bytes(bytes, observer)?;
            }
        }
        observer.observe(&completed_response.is_some())?;
        observer.observe(completed_record)
    }
}

fn observe_data(
    data: &PacketNativeFreshRestoreAllocationData,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let PacketNativeFreshRestoreAllocationData { scope, storage } = data;
    let PacketNativeFreshRestoreAllocationScope {
        native_pid,
        session,
        incarnation,
        node,
        owner,
        owner_generation,
        owner_binding,
        world,
        prepared_token,
        admission,
        closed_gate_receipt,
        nonce,
        assigned_query,
        completed_admit_request,
        completed_admit_response,
        ack_context,
    } = scope;
    observer.observe(native_pid)?;
    observer.observe(session)?;
    observer.observe(incarnation)?;
    observer.observe(node)?;
    observer.observe(owner)?;
    observer.observe(owner_generation)?;
    observer.observe(owner_binding)?;
    observer.observe(world)?;
    observer.observe(prepared_token)?;
    observer.observe(admission)?;
    observer.observe(closed_gate_receipt)?;
    for bytes in [
        nonce,
        assigned_query,
        completed_admit_request,
        completed_admit_response,
        ack_context,
    ] {
        observer.observe(bytes)?;
    }
    let PacketNativeFreshRestoreAllocationStorage {
        current_retained_bytes,
        query_retained_growth_bytes,
        prepare_retained_growth_bytes,
        query_transient_bytes,
        prepare_transient_bytes,
        declared_counter_scratch_bytes,
    } = storage;
    for quantity in [
        current_retained_bytes,
        query_retained_growth_bytes,
        prepare_retained_growth_bytes,
        query_transient_bytes,
        prepare_transient_bytes,
        declared_counter_scratch_bytes,
    ] {
        observer.observe(quantity)?;
    }
    Ok(())
}

fn observe_proof(
    proof: &PacketNativeFreshRestoreAllocationProof,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let PacketNativeFreshRestoreAllocationProof {
        schema,
        algorithm,
        context_digest,
        mac,
    } = proof;
    observer.observe(schema)?;
    observer.observe(algorithm)?;
    observer.observe(context_digest)?;
    observer.observe(mac)
}

fn observe_bytes(bytes: &Vec<u8>, observer: &mut MetadataObserver) -> Result<(), ProviderError> {
    observer.vector::<u8>(bytes.capacity())?;
    observer.observe(&bytes.len())
}
