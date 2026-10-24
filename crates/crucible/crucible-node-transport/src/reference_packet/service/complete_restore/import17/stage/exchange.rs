//! Joins complete carried stage proofs, receipts and predecessor exchanges.
//!
//! The borrowed transcript has no verified bit or live conversion. Every call
//! checks its actual records again. Current Source/native custody, full Stage18
//! selection, construction admission, literal publication and physical effects
//! remain mandatory duties of the enclosing issuer or adopter.

use super::*;
use crate::bodies::{MethodResult, decode_request, decode_response};
use crate::envelope::Envelope;
use crucible_node_format::{ContentRef, Visibility};
use serde::Serialize;

/// Borrows one complete assigned exchange and its independently derived DATA.
///
/// Typed records must match the extensions actually carried by the Envelopes.
/// Possessing this view certifies neither their provenance nor native effects.
pub struct PacketNativeImport18StageExchangeData<'a> {
    /// Borrows the full stage binding carried by the assigned original.
    pub binding: &'a PacketNativeImport17StageBinding,
    /// Borrows the independently derived birth, binding and assignment context.
    pub context: &'a PacketNativeImport17StageContext,
    /// Borrows the phase proof actually carried by the original.
    pub proof: &'a PacketNativeImport17StageProof,
    /// Borrows the phase receipt actually carried by the terminal.
    pub receipt: &'a PacketNativeImport17StageReceipt,
    /// Borrows the complete original including its proof extension.
    pub original: &'a Envelope,
    /// Borrows the complete terminal including its receipt extension.
    pub terminal: &'a Envelope,
}

impl PacketNativeImport18StageExchangeData<'_> {
    /// Authenticates all carried stage DATA against one independent birth digest.
    ///
    /// The caller independently admits binding/Envelope canonicalization and
    /// validation, crypto work and its actual enclosing controls before entry.
    /// Temporary typed baseline decoding is separately funded; its result stays
    /// inside this call. This performs no transport publication or native effect.
    ///
    /// # Errors
    /// Refuses changed birth, binding, target, assignment, phase, correlation,
    /// status, key, MAC, missing extension or unequal carried typed records.
    pub fn authenticate_data(
        &self,
        key: &[u8; 32],
        birth_context_digest: &[u8; 32],
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.context.authenticate_stage18_data(
            self.binding,
            birth_context_digest,
            self.original,
            maximum_frame_bytes,
        )?;
        verify_native_import17_stage_proof_data(key, self.context, self.proof)?;
        same_carried(
            self.original,
            self.binding.phase.proof_extension(),
            self.proof,
            MAXIMUM_NATIVE_IMPORT17_STAGE_PROOF_BYTES,
        )?;

        self.authenticate_baseline_terminal()?;
        let assigned_response = native_import18_stage_assigned_response_digest(
            self.original,
            self.terminal,
            self.binding.phase,
            maximum_frame_bytes,
        )?;
        verify_native_import17_stage_receipt_data(
            key,
            self.context,
            &assigned_response,
            self.receipt,
        )?;
        same_carried(
            self.terminal,
            self.binding.phase.receipt_extension(),
            self.receipt,
            MAXIMUM_NATIVE_IMPORT17_STAGE_RECEIPT_BYTES,
        )
    }

    fn authenticate_baseline_terminal(&self) -> Result<(), ProviderError> {
        let request = decode_request(self.original.method, &self.original.body)?;
        let response = decode_response(&request, &self.terminal.body)?;
        let target = &self.binding.target;
        let matches = match (self.binding.phase, response.result.as_ref()) {
            (PacketNativeImport17Stage::Arm, Some(MethodResult::Activate(result))) => {
                result.staged_owner_ids.len() == 1
                    && result.staged_owner_ids.first() == Some(&target.owner)
            }
            (PacketNativeImport17Stage::World, Some(MethodResult::WorldActivate(result))) => {
                result.armed_owner_ids.len() == 1
                    && result.armed_owner_ids.first() == Some(&target.owner)
            }
            (PacketNativeImport17Stage::FirstObserve, Some(MethodResult::Observe(result))) => {
                let [batch] = result.observations.as_slice() else {
                    return Err(invalid());
                };
                result.complete
                    && result.next_sequence.get() == 1
                    && batch.execution_owner_id == target.owner
                    && batch.owner_binding_hash == target.binding_hash
                    && batch.world_binding_hash == target.world
                    && batch.activation_id == target.activation
                    && batch.world_generation == target.generation
                    && batch.owner_generation == target.owner_generation
                    && Some(&batch.operation_id) == self.original.request_id.0.as_ref()
                    && batch.grant_id.is_none()
                    && batch.first_sequence.get() == 0
                    && batch.last_sequence.get() == 0
                    && batch.events.is_empty()
                    && batch.visibility == Visibility::Staged
                    && batch.extensions.is_empty()
            }
            _ => false,
        };
        if !matches {
            return Err(invalid());
        }
        Ok(())
    }

    /// Authenticates this exchange and both complete canonical pair references.
    ///
    /// Reference equality does not prove actual literal publication. The caller
    /// retains and authenticates its original SDK/journal and physical owners.
    /// Canonical output and reference construction require separate admission.
    ///
    /// # Errors
    /// Refuses any exchange failure or a changed full original/terminal reference.
    pub fn authenticate_pair_data(
        &self,
        pair: &PacketNativeImport17StagePairData,
        key: &[u8; 32],
        birth_context_digest: &[u8; 32],
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_data(key, birth_context_digest, maximum_frame_bytes)?;
        pair.validate_data()?;
        authenticate_reference(&pair.original, self.original, maximum_frame_bytes)?;
        authenticate_reference(&pair.terminal, self.terminal, maximum_frame_bytes)
    }
}

impl PacketNativeImport17StageBinding {
    /// Checks complete authenticated predecessors for this exact fresh target.
    ///
    /// Arm has none; World has completed Arm; first Observe has completed Arm
    /// and World, including World's own reference to that same Arm. Every
    /// exchange must retain the same import, Source, scope, target, Prepare,
    /// Commit and Hold correspondence. Each phase keeps its separate allocation.
    /// These checks issue no Source grant, SDK completion or physical witness.
    /// The caller independently admits the complete bounded transcript work.
    ///
    /// # Errors
    /// Refuses a missing/extra predecessor, foreign phase, birth/key/MAC, full
    /// pair reference, shared target/import history or inconsistent World chain.
    pub fn authenticate_predecessors_data(
        &self,
        arm: Option<&PacketNativeImport18StageExchangeData<'_>>,
        world: Option<&PacketNativeImport18StageExchangeData<'_>>,
        key: &[u8; 32],
        birth_context_digest: &[u8; 32],
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        match (self.phase, arm, world) {
            (PacketNativeImport17Stage::Arm, None, None) => Ok(()),
            (PacketNativeImport17Stage::World, Some(arm), None) => {
                self.authenticate_predecessor_binding(arm.binding, PacketNativeImport17Stage::Arm)?;
                arm.authenticate_pair_data(
                    self.arm.as_ref().ok_or_else(invalid)?,
                    key,
                    birth_context_digest,
                    maximum_frame_bytes,
                )
            }
            (PacketNativeImport17Stage::FirstObserve, Some(arm), Some(world)) => {
                self.authenticate_predecessor_binding(arm.binding, PacketNativeImport17Stage::Arm)?;
                self.authenticate_predecessor_binding(
                    world.binding,
                    PacketNativeImport17Stage::World,
                )?;
                world.authenticate_pair_data(
                    self.world.as_ref().ok_or_else(invalid)?,
                    key,
                    birth_context_digest,
                    maximum_frame_bytes,
                )?;
                same_pair(
                    self.arm.as_ref().ok_or_else(invalid)?,
                    world.binding.arm.as_ref().ok_or_else(invalid)?,
                )?;
                world.binding.authenticate_predecessors_data(
                    Some(arm),
                    None,
                    key,
                    birth_context_digest,
                    maximum_frame_bytes,
                )
            }
            _ => Err(invalid()),
        }
    }

    fn authenticate_predecessor_binding(
        &self,
        previous: &PacketNativeImport17StageBinding,
        phase: PacketNativeImport17Stage,
    ) -> Result<(), ProviderError> {
        if previous.phase != phase
            || self.import_binding_digest != previous.import_binding_digest
            || self.source_birth != previous.source_birth
            || self.source_runtime != previous.source_runtime
            || self.scope_proof != previous.scope_proof
            || self.target != previous.target
            || self.hold != previous.hold
            || bounded(&self.prepare, MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES)?
                != bounded(
                    &previous.prepare,
                    MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES,
                )?
            || bounded(&self.commit, MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES)?
                != bounded(
                    &previous.commit,
                    MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES,
                )?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn same_pair(
    left: &PacketNativeImport17StagePairData,
    right: &PacketNativeImport17StagePairData,
) -> Result<(), ProviderError> {
    if left.original != right.original || left.terminal != right.terminal {
        return Err(invalid());
    }
    Ok(())
}

fn same_carried(
    envelope: &Envelope,
    extension: &str,
    typed: &impl Serialize,
    maximum: usize,
) -> Result<(), ProviderError> {
    let carried = envelope.extensions.get(extension).ok_or_else(invalid)?;
    if bounded(typed, maximum)? != bounded(carried, maximum)? {
        return Err(invalid());
    }
    Ok(())
}

fn authenticate_reference(
    reference: &ContentRef,
    envelope: &Envelope,
    maximum: usize,
) -> Result<(), ProviderError> {
    crate::connection::serialized_credit(envelope, maximum)?;
    let encoded = bounded(envelope, maximum)?;
    if reference != &canonical::content_ref(&encoded, "application/json")? {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
