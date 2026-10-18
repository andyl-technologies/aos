//! Owns selected Commit preparation, same-socket installation and proof publication.
//!
//! All owners enter the endpoint capsule before fallible work. Proof frames and
//! their correlation nodes are prepared before the SDK/model effect; the actual
//! held token enables publication, followed by the genuinely assigned response.

use super::*;
use crate::client::{DeadlineStream, ExchangeDeadline};
use crate::protocol_snapshot::PreparedArchivedNativeProtocolMapping;
use crate::reference_packet::service::ack_emitter::{
    NativeAckBoot, OriginalCompleteRestoreCommit, VerifiedCompleteRestoration,
    VerifiedCompleteRestorationHeld,
};
use std::cell::RefCell;

mod frames;

pub(super) mod settled17;

pub(super) struct RestoreCommitFlight<S: ProviderStream> {
    mapping: Option<Rc<RefCell<PreparedArchivedNativeProtocolMapping>>>,
    admission: Option<VerifiedCompleteRestoration>,
    held: Option<VerifiedCompleteRestorationHeld>,
    proof: Option<PreparedOriginalRestoreHeldProof<S>>,
    recovered_connection: Option<Connection<S>>,
    completed: Option<ExchangeRecord>,
    proof_charge: usize,
    proof_allocation: Option<OriginalRestoreHeldProofAllocationQuote>,
}

impl PacketEndpoint<DeadlineStream> {
    pub(super) fn restore_original_commit(
        &mut self,
        request: &Envelope,
        deadline: &ExchangeDeadline,
    ) -> Result<bool, ProviderError> {
        self.ensure_complete_origin()?;
        deadline.remaining()?;
        if !self.restore_protocol_attempted
            || self.restore_commit.is_some()
            || self.records.len() >= EXCHANGES
        {
            return Err(refused());
        }
        self.restore_commit = Some(RestoreCommitFlight {
            mapping: None,
            admission: None,
            held: None,
            proof: None,
            recovered_connection: None,
            completed: None,
            proof_charge: 0,
            proof_allocation: None,
        });
        let flight = self.restore_commit.as_mut().ok_or_else(refused)?;
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        connection.prepare_original_complete_restore_input_mapping_into(&mut flight.mapping)?;
        let mapping = flight.mapping.as_ref().ok_or_else(refused)?;
        let boot = self.canonical_ack_boot.as_ref().ok_or_else(refused)?;
        NativeAckBoot::verify_complete_restore_commit_into(
            boot,
            OriginalCompleteRestoreCommit {
                hello: &self.complete.as_ref().ok_or_else(refused)?.hello,
                original: request,
                mapping,
                connection,
                control: &self.native,
            },
            &mut flight.admission,
        )?;
        flight.proof_allocation =
            Some(connection.retain_original_complete_restore_held_proof_allocation()?);
        let originals = {
            let evidence = flight
                .admission
                .as_ref()
                .ok_or_else(refused)?
                .original_prepared_gate_evidence(connection)?;
            let (originals, charge) = frames::plan(
                &self.authority,
                request,
                self.next_sequence,
                &evidence.0,
                &evidence.1,
            )?;
            flight.proof_charge = self
                .transport_credit
                .checked_add(charge)
                .filter(|charge| *charge <= MAXIMUM_PACKET_TRANSPORT_BYTES)
                .ok_or_else(refused)?;
            originals
        };
        let Some(Transport::Connected(connection)) = self.transport.take() else {
            return Err(refused());
        };
        // This field is installed before any schema callback or literal-bank
        // reservation. No local unwind can lose the actual connection owner.
        flight.proof =
            Some(connection.unprepared_original_restore_held_proof(request.clone(), originals));
        let proof = flight.proof.as_mut().ok_or_else(refused)?;
        let proof_allocation = flight.proof_allocation.as_ref().ok_or_else(refused)?;
        proof.prebuild_in_place(proof_allocation)?;
        let facts = proof.original_retained_metadata_facts()?;
        let connection = proof.connection_mut()?;
        proof_allocation.authenticate_reconciled_plan(connection, &facts)?;
        connection.install_original_complete_restoration(&mut flight.admission, mapping)?;
        connection.authenticate_installed_complete_restoration(mapping)?;
        NativeAckBoot::install_complete_restore_model_into(
            boot,
            connection,
            mapping,
            &mut self.native,
            &mut flight.held,
        )?;
        self.transport_credit = flight.proof_charge;
        let held = flight.held.as_ref().ok_or_else(refused)?;
        proof.activate_original_held(held)?;
        proof.publish(&mut frames::validate_ack)?;
        PreparedOriginalRestoreHeldProof::take_completed_into(
            &mut flight.proof,
            &mut flight.recovered_connection,
            &mut flight.completed,
        )?;
        self.transport = Some(Transport::Connected(
            flight.recovered_connection.take().ok_or_else(refused)?,
        ));
        let completed = flight.completed.as_ref().ok_or_else(refused)?;
        let first = completed.originals().first().ok_or_else(refused)?;
        if first.sequence.get() != self.next_sequence {
            return Err(refused());
        }
        self.next_sequence = completed
            .originals()
            .last()
            .ok_or_else(refused)?
            .sequence
            .get()
            .checked_add(1)
            .ok_or_else(refused)?;
        let Some(Transport::Connected(connection)) = self.transport.as_mut() else {
            return Err(refused());
        };
        let mut assigned = connection
            .prepare_original_complete_restore_commit_response(request, held, completed)?;
        let next = {
            let original = assigned.original()?;
            if original.sequence.get() != self.next_sequence {
                return Err(refused());
            }
            original.sequence.get().checked_add(1).ok_or_else(refused)?
        };
        assigned.seal_original_commit_receipt(held)?;
        assigned.publish()?;
        drop(assigned);
        held.retain_completed_control_evidence(connection, request, &mut self.native)?;
        deadline.remaining()?;
        self.records
            .push(flight.completed.take().ok_or_else(refused)?);
        self.next_sequence = next;
        self.held = false;
        Ok(true)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original selected Commit held")
}

mod settled_capture_cut17;

pub(super) use settled_capture_cut17::observation17_host_cut_counter_scratch_data;
