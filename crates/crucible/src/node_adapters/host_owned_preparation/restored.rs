//! Attaches fresh public preparation to the same restored finite-model owner.
//!
//! The source capsule remains historical evidence. A fresh private session and
//! current Ready are created only after native restoration succeeds; they never
//! reclassify restored custody as initial realization.

use super::*;

impl HostModelNode {
    pub(super) fn retain_restored_owned_model_preparation(
        &mut self,
        target: &ActivationRecord,
    ) -> Result<(), OperationFailure> {
        self.authenticate_restored_owned_model()?;
        let history = self
            .public_model_history
            .as_ref()
            .ok_or_else(|| failure("restored finite-model source history is absent"))?;
        if &history.target != target
            || target.owners.is_empty()
            || target.owners.len() > 64
            || target
                .owners
                .windows(2)
                .any(|pair| pair[0].owner >= pair[1].owner)
            || !self
                .route
                .owners
                .iter()
                .all(|owner| target.owners.contains(owner))
            || self.public_model_preparation.is_some()
        {
            return Err(failure(
                "restored finite-model preparation has a foreign target roster",
            ));
        }
        let remaining = self.restored_preparation_credit()?;
        let native_length = credit::native_ready_length(self)?;
        let remaining = remaining
            .checked_sub(native_length)
            .ok_or_else(|| failure("restored native readiness exceeds preparation credit"))?;
        let initial_native =
            canonical::content_ref(self.initial.as_slice(), "application/octet-stream")
                .map_err(|error| failure(&error.to_string()))?;
        let native_ready_bytes = self.receipt_bytes("host-model-owned-inactive-v1");
        if native_ready_bytes.len() != native_length {
            return Err(failure(
                "restored native readiness has another credited geometry",
            ));
        }
        let native_ready = canonical::content_ref(&native_ready_bytes, "application/octet-stream")
            .map_err(|error| failure(&error.to_string()))?;
        let binding = self
            .binding
            .identity()
            .map_err(|error| failure(&error.to_string()))?;
        let session_length = credit::restored_session_length(
            self,
            &initial_native,
            &native_ready,
            &binding,
            &target.owners,
            remaining,
        )?;
        let session_bytes = credit::encode_session(
            self,
            (&initial_native, &native_ready, &binding),
            &target.owners,
        )?;
        if session_bytes.len() != session_length {
            return Err(failure(
                "restored session differs from precredited geometry",
            ));
        }
        let session = canonical::content_ref(&session_bytes, "application/json")
            .map_err(|error| failure(&error.to_string()))?;
        let token = Id::new(format!("host/model-prepared/{}", session.hash.digest))
            .map_err(|error| failure(&error.to_string()))?;
        let mut world_owners = Vec::new();
        world_owners
            .try_reserve_exact(target.owners.len())
            .map_err(|_| failure("restored owner roster reservation failed"))?;
        world_owners.extend_from_slice(&target.owners);
        self.public_model_preparation = Some(OriginalOwnedModelPreparation {
            anchor: Rc::clone(&self.original_model_session),
            token,
            session,
            session_bytes,
            initial_native,
            native_ready,
            native_ready_bytes,
            world_owners,
            ready: None,
            previous: Some(history.original.reference.clone()),
        });
        Ok(())
    }

    fn authenticate_restored_owned_model(&self) -> Result<(), OperationFailure> {
        let history = self
            .public_model_history
            .as_ref()
            .ok_or_else(|| failure("restored finite-model source custody is absent"))?;
        let supported = matches!(self.model.as_ref(), Some(HostModel::ScriptedSource(script))
            if script.kind() == super::super::super::ScriptedRequestKind::Block)
            || matches!(self.model.as_ref(), Some(HostModel::Io(model)) if model.block_device().is_some());
        if !supported
            || self.preparation_origin != HostPreparationOrigin::Restored
            || self.prepared_continuation.is_none()
            || self.quarantined
            || !self.completed.is_empty()
            || !self.failed.is_empty()
            || !self.input_history.is_empty()
            || self.staged.is_some()
            || self.recorded_ingress.is_some()
            || self.condition_preservation
            || self.route.owners.len() != 1
            || history.target.boundary != self.boundary
            || history.target.world_binding_hash != self.world_hash
            || self
                .readiness
                .as_ref()
                .is_some_and(|(world, _)| world != &history.target)
            || self.capture()?.as_slice() != self.initial.as_slice()
            || !self
                .binding
                .compatibility
                .implementation
                .formats
                .contains(&continuation::host_public_owned_model_continuation_schema()?)
        {
            return Err(failure(
                "fresh public preparation lost its restored native custody",
            ));
        }
        history
            .original
            .reference
            .verify(&history.original.bytes)
            .map_err(|error| failure(&error.to_string()))?;
        for body in &history.evidence {
            body.reference
                .verify(&body.bytes)
                .map_err(|error| failure(&error.to_string()))?;
        }
        if let Some(preparation) = &self.public_model_preparation
            && preparation.previous.as_ref() != Some(&history.original.reference)
        {
            return Err(failure(
                "restored public session has another original source",
            ));
        }
        Ok(())
    }

    pub(super) fn authenticate_owned_model_preparation(&self) -> Result<(), OperationFailure> {
        if self.preparation_origin == HostPreparationOrigin::Original {
            if self.public_model_history.is_some()
                || self
                    .public_model_preparation
                    .as_ref()
                    .is_some_and(|session| session.previous.is_some())
            {
                return Err(failure(
                    "initial finite-model preparation has restored ancestry",
                ));
            }
            return self.authenticate_original_owned_model();
        }
        self.authenticate_restored_owned_model()
    }

    pub(super) fn restored_preparation_credit(&self) -> Result<usize, OperationFailure> {
        let Some(history) = &self.public_model_history else {
            return Ok(self.limits.maximum_capture_bytes);
        };
        history.evidence.iter().try_fold(
            self.limits
                .maximum_capture_bytes
                .checked_sub(history.original.bytes.len())
                .and_then(|remaining| remaining.checked_sub(history.target_credit))
                .ok_or_else(|| failure("original restored capsule exhausts preparation credit"))?,
            |remaining, body| {
                remaining
                    .checked_sub(body.bytes.len())
                    .ok_or_else(|| failure("restored source history exhausts preparation credit"))
            },
        )
    }
}
