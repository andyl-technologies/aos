//! Retains each unassigned bootstrap DTO before validation or terminal refusal.

use super::*;
use crate::envelope::{Envelope, MessageKind, Method};
use crate::reference_packet::service::complete_restore::import18::PacketNativeImport18SelectedLaunchWireData;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    PacketNativeImport18BootstrapAckProof, PacketNativeImport18BootstrapRequest,
};
use crate::retained_metadata::{MetadataObserver, requested_metadata_backing_storage_data};
use serde::Deserialize;
use std::rc::{Rc, Weak};

/// Names the current typed construction prefix without granting a native phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in super::super::super) enum Step {
    /// Decodes and retains the complete request Envelope.
    Envelope,
    /// Decodes and retains its exact bootstrap request body.
    Request,
    /// Decodes and retains its sole bootstrap proof extension.
    Proof,
}

/// Preserves fixed serde coordinates for the actual failed decoder prefix.
pub(super) struct Failure {
    /// Identifies the decoder that produced these coordinates.
    pub(super) step: Step,
    /// Records serde's allocation-free error classification.
    pub(super) category: serde_json::error::Category,
    /// Records the decoder's original line coordinate.
    pub(super) line: usize,
    /// Records the decoder's original column coordinate.
    pub(super) column: usize,
}

/// Retains the actual output prefix and fixed serde failure coordinates.
pub(in super::super::super) struct Attempt {
    /// Spends the external occurrence before any guard or decoder.
    pub(super) started: bool,
    /// Records completion only after aggregate original guards.
    pub(super) complete: bool,
    /// Permanently closes loans after either construction or terminal refusal.
    pub(super) failed: bool,
    /// Preserves the original nonrenewing operational cut.
    pub(super) cut: Option<OperationalDeadline>,
    /// Associates DATA with the actual retained parsed launch allocation.
    pub(super) launch: Option<Weak<PacketNativeImport18SelectedLaunchWireData>>,
    /// Retains the admitted R/T/S quote before typed allocation.
    pub(super) row: Option<[usize; 3]>,
    /// Identifies the spent decoder prefix even when validation fails.
    pub(super) step: Option<Step>,
    /// Retains the complete decoded envelope before target validation.
    pub(super) envelope: Option<Envelope>,
    /// Retains the decoded body before Recipe and initial-row joins.
    pub(super) request: Option<PacketNativeImport18BootstrapRequest>,
    /// Retains structural proof DATA without asserting MAC verification.
    pub(super) proof: Option<PacketNativeImport18BootstrapAckProof>,
    /// Retains fixed serde failure coordinates without an owned diagnostic.
    pub(super) failure: Option<Failure>,
}

impl Attempt {
    /// Initializes retained slots without allocating or inspecting input.
    pub(in super::super::super) fn empty_data() -> Self {
        Self {
            started: false,
            complete: false,
            failed: false,
            cut: None,
            launch: None,
            row: None,
            step: None,
            envelope: None,
            request: None,
            proof: None,
            failure: None,
        }
    }

    fn authenticate_alias(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<(), ProviderError> {
        if let Some(launch) = &self.launch
            && !Weak::ptr_eq(
                launch,
                &Rc::downgrade(original.parsed.shared_launch_data()?),
            )
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Checks the bound original alias, cut, channel and same borrowed live SDK.
    ///
    /// # Errors
    /// Refuses changed association, expiry, channel custody or SDK revocation.
    pub(super) fn guard(
        &self,
        original: &OriginalImport18RawBootstrap,
        operands: &BootstrapAckOperands<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_alias(original)?;
        if self.cut != Some(original.cut) || original.cut.is_expired() {
            return Err(refused());
        }
        original.authenticate_channel()?;
        operands.ensure_current_authority_data()
    }

    /// Stores one typed output before checking its correspondence as DATA.
    ///
    /// # Errors
    /// Refuses an out-of-order step, malformed DTO or changed original binding.
    pub(super) fn construct_step(
        &mut self,
        step: Step,
        original: &OriginalImport18RawBootstrap,
        operands: &BootstrapAckOperands<'_>,
        value: &Value,
        closed: &prewalk::Closed<'_>,
    ) -> Result<(), ProviderError> {
        if self.row.is_none() || self.failure.is_some() {
            return Err(refused());
        }
        match step {
            Step::Envelope => {
                if self.step.is_some() || self.envelope.is_some() {
                    return Err(refused());
                }
                self.step = Some(step);
                match Envelope::deserialize(value) {
                    Ok(envelope) => self.envelope = Some(envelope),
                    Err(error) => return Err(self.retain_failure(step, error)),
                }
                let envelope = self.envelope.as_ref().ok_or_else(refused)?;
                envelope.validate()?;
                if envelope.message != MessageKind::Request
                    || envelope.method != Method::NativeImport18Bootstrap
                {
                    return Err(refused());
                }
                operands.authenticate_bootstrap_envelope_target_data(envelope)?;
                let hello = original.hello_envelope.data(original.cut)?;
                if hello.sequence.get().checked_add(1) != Some(envelope.sequence.get())
                    || hello.request_id == envelope.request_id
                    || value.get("body").and_then(Value::as_object) != Some(&envelope.body)
                    || value
                        .get("extensions")
                        .and_then(Value::as_object)
                        .is_none_or(|fields| fields.iter().ne(envelope.extensions.iter()))
                {
                    return Err(refused());
                }
            }
            Step::Request => {
                if self.step != Some(Step::Envelope)
                    || self.envelope.is_none()
                    || self.request.is_some()
                {
                    return Err(refused());
                }
                self.step = Some(step);
                match PacketNativeImport18BootstrapRequest::deserialize(closed.request) {
                    Ok(request) => self.request = Some(request),
                    Err(error) => return Err(self.retain_failure(step, error)),
                }
                let request = self.request.as_ref().ok_or_else(refused)?;
                request.validate_data()?;
                let expected_recipe = original
                    .typed_bodies_data()?
                    .recipe
                    .announced_identity_data();
                let expected_initial = original
                    .header
                    .as_ref()
                    .ok_or_else(refused)?
                    .initial_funding_data()?;
                if request.recipe_identity.as_slice() != expected_recipe
                    || request.initial_funding != expected_initial
                {
                    return Err(refused());
                }
            }
            Step::Proof => {
                if self.step != Some(Step::Request)
                    || self.request.is_none()
                    || self.proof.is_some()
                {
                    return Err(refused());
                }
                self.step = Some(step);
                match PacketNativeImport18BootstrapAckProof::deserialize(closed.proof) {
                    Ok(proof) => self.proof = Some(proof),
                    Err(error) => return Err(self.retain_failure(step, error)),
                }
                self.proof.as_ref().ok_or_else(refused)?.validate_data()?;
            }
        }
        Ok(())
    }

    fn retain_failure(&mut self, step: Step, error: serde_json::Error) -> ProviderError {
        self.failure = Some(Failure {
            step,
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        });
        refused()
    }

    /// Counts every surviving decoded allocation even after terminal refusal.
    ///
    /// # Errors
    /// Refuses foreign association, metadata overflow or checked capacity sums.
    pub(in super::super::super) fn retained_requested_bytes_data(
        &self,
        original: &OriginalImport18RawBootstrap,
    ) -> Result<usize, ProviderError> {
        self.authenticate_alias(original)?;
        self.requested_storage_data()
    }

    /// Counts actual DTO backing without accepting an original-owner association.
    ///
    /// # Errors
    /// Refuses metadata limits, unsupported layouts or checked capacity overflow.
    pub(super) fn requested_storage_data(&self) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        if let Some(envelope) = &self.envelope {
            observe_envelope_data(envelope, &mut observer)?;
        }
        if let Some(request) = &self.request {
            let PacketNativeImport18BootstrapRequest {
                schema,
                recipe_identity,
                initial_funding: _,
            } = request;
            observer.observe(schema)?;
            observer.observe(recipe_identity)?;
        }
        if let Some(proof) = &self.proof {
            let PacketNativeImport18BootstrapAckProof {
                schema,
                algorithm,
                context_digest,
                mac,
            } = proof;
            observer.observe(schema)?;
            observer.observe(algorithm)?;
            observer.observe(context_digest)?;
            observer.observe(mac)?;
        }
        size_of::<Self>()
            .checked_add(requested_metadata_backing_storage_data(&observer.finish())?)
            .ok_or_else(exhausted)
    }

    /// Borrows the complete typed prefix after every construction guard passes.
    ///
    /// # Errors
    /// Refuses incomplete or terminally failed construction.
    pub(super) fn data(
        &self,
    ) -> Result<
        (
            &Envelope,
            &PacketNativeImport18BootstrapRequest,
            &PacketNativeImport18BootstrapAckProof,
        ),
        ProviderError,
    > {
        if !self.complete || self.failed || self.step != Some(Step::Proof) || self.failure.is_some()
        {
            return Err(refused());
        }
        Ok((
            self.envelope.as_ref().ok_or_else(refused)?,
            self.request.as_ref().ok_or_else(refused)?,
            self.proof.as_ref().ok_or_else(refused)?,
        ))
    }
}

/// Counts every owning Envelope field using the ordinary metadata census.
///
/// # Errors
/// Refuses metadata limits, unsupported layouts or checked capacity overflow.
pub(in super::super) fn observe_envelope_data(
    envelope: &Envelope,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let Envelope {
        protocol,
        message: _,
        session_id,
        incarnation_id,
        node_id,
        execution_owner_id,
        capture_owner_id,
        request_id,
        operation_id,
        sequence: _,
        method: _,
        body,
        extensions,
    } = envelope;
    observer.observe(protocol)?;
    observer.observe(session_id)?;
    observer.observe(incarnation_id)?;
    observer.observe(node_id)?;
    observer.observe(execution_owner_id)?;
    observer.observe(capture_owner_id)?;
    observer.observe(request_id)?;
    observer.observe(operation_id)?;
    observer.observe(body)?;
    observer.observe(extensions)?;
    Ok(())
}
