//! Compares an actual Capture17 checkpoint through the defining native owner.
//!
//! A borrowed field view joins the actual Source-signed Capture request to the
//! same stopped-model comparer used by signed Observe17. It grants neither
//! currentness nor a native action: the private same-Boot lender, Source MAC,
//! full ancestry and independent prospective debit remain mandatory. Every
//! failed comparison stays retained in the caller's actual checkpoint slot.

use super::*;
use crate::reference_packet::service::{
    complete_restore::activation::PacketRestorationActivationScope,
    restored_settled_capture::PacketRestoredSettledCaptureRequest,
};

/// Borrows only the exact fields consumed by the defining stopped-model check.
#[derive(Clone, Copy)]
pub(super) struct CheckpointFields17<'a> {
    scope: &'a PacketRestorationActivationScope,
    current_record: &'a ContentRef,
    current_model: &'a ContentRef,
    history_next_sequence: U64,
    capture: bool,
}

impl<'a> CheckpointFields17<'a> {
    pub(super) fn observation_data(request: &'a PacketRestoredInputReactive17Request) -> Self {
        let PacketRestoredInputReactive17Request {
            schema: _,
            command: _,
            scope,
            first_observation: _,
            current_record,
            current_model,
            history_prefix: _,
            history_next_sequence,
            native_allocation: _,
        } = request;
        Self {
            scope,
            current_record,
            current_model,
            history_next_sequence: *history_next_sequence,
            capture: false,
        }
    }

    fn capture_data(request: &'a PacketRestoredSettledCaptureRequest) -> Self {
        let PacketRestoredSettledCaptureRequest {
            schema: _,
            scope,
            capture: _,
            capture_owner: _,
            capture_operation: _,
            runtime_object: _,
            coordinator_checkpoint: _,
            parent_archive: _,
            first_observation: _,
            current_record,
            current_model,
            history_prefix: _,
            history_next_sequence,
            native_schema: _,
            native_allocation: _,
        } = request;
        Self {
            scope,
            current_record,
            current_model,
            history_next_sequence: *history_next_sequence,
            capture: true,
        }
    }
}

impl PacketControl {
    /// Quotes a genuine Capture request's unchanged stopped model checkpoint.
    ///
    /// This allocation-free DATA projection borrows the actual retained prior
    /// original and full Capture fields. Neither a matching cached pair nor this
    /// row supplies the actual prior published owner, Source proof or debit.
    ///
    /// # Errors
    /// Refuses changed actual cache custody, unsupported model or active-grant
    /// state, overflow or an independently short complete bound.
    pub(crate) fn quote_capture17_checkpoint_data<'previous>(
        &self,
        previous: &'previous Envelope,
        request: &PacketRestoredSettledCaptureRequest,
        maximum: usize,
    ) -> Result<NativeObservation17CheckpointStorageData<'previous>, ProviderError> {
        self.authenticate_capture17_stopped_checkpoint_state_data(request)?;
        self.quote_current_checkpoint17_fields_data(
            previous,
            CheckpointFields17::capture_data(request),
            maximum,
        )
    }

    /// Retains and compares the actual pre-Capture checkpoint after native debit.
    ///
    /// The caller retains its same actual published-original loan throughout
    /// this check. Canonical/hash banks are created only after that private
    /// scope independently spends this row; no Capture DTO is converted to an
    /// Observe request, original or permission.
    ///
    /// # Errors
    /// Refuses reused destination, changed Control/original/cache custody,
    /// serialization/hash failure, stale native inventory or restoration proof.
    pub(crate) fn authenticate_capture17_checkpoint_into_data(
        &self,
        previous: &Envelope,
        request: &PacketRestoredSettledCaptureRequest,
        storage: &NativeObservation17CheckpointStorageData<'_>,
        destination: &mut Option<NativeObservation17CheckpointAttempt>,
    ) -> Result<(), ProviderError> {
        self.authenticate_capture17_stopped_checkpoint_state_data(request)?;
        self.authenticate_current_checkpoint17_into_data(
            previous,
            CheckpointFields17::capture_data(request),
            storage,
            destination,
        )
    }

    // These live eligibility checks allocate nothing. Full first/World/Source
    // scope authority still comes only from the actual lender and private scope.
    fn authenticate_capture17_stopped_checkpoint_state_data(
        &self,
        request: &PacketRestoredSettledCaptureRequest,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id()
            || self.fenced
            || !self.immediate
            || !self.restoration_activation_required
            || self.complete_restored_hold.is_none()
            || self.complete_restored_evidence.is_none()
            || self.original_physical_gate_held()?
            || self.current_operation.is_some()
            || self.active.as_ref().is_none_or(|active| {
                active.activation_id != request.scope.target.activation
                    || active.world_generation != request.scope.target.generation
                    || active.world_binding_hash != request.scope.target.world
            })
        {
            return Err(refused());
        }
        // The Capture-specific cut keeps its output-drained requirement; the
        // Observe inventory borrower alone intentionally permits retained output.
        self.program
            .authenticate_original_capture_cut(request.capture.cut)?;
        Ok(())
    }

    // Matching proof references only rejoin retained cache DATA. The genuine
    // current lender has already selected the actual privately published owner.
    pub(super) fn authenticate_current_checkpoint17_fields_data(
        &self,
        previous: &Envelope,
        fields: CheckpointFields17<'_>,
    ) -> Result<(), ProviderError> {
        let id = previous.request_id.0.as_ref().ok_or_else(refused)?;
        let (_, reply) = self.originals.get(id).ok_or_else(refused)?;
        let (model, restored) = match (previous.method, reply.evidence.as_slice()) {
            (Method::Observe, [model, restored]) => (model, restored),
            (Method::Input, [_, _, _, model, restored])
                if previous.extensions.len() == 1
                    && previous
                        .extensions
                        .contains_key(RESTORED_INPUT_REACTIVE17_FEATURE) =>
            {
                (model, restored)
            }
            _ => return Err(refused()),
        };
        if &model.0 != fields.current_model
            || &restored.0 != fields.current_record
            || self.content.get(&model.0) != Some(&model.1)
            || self.content.get(&restored.0) != Some(&restored.1)
            || previous.sequence >= fields.history_next_sequence
            || !matches!(previous.method, Method::Observe | Method::Input)
        {
            return Err(refused());
        }
        let mut owners = self.originals.iter().filter(|(_, (_, candidate))| {
            candidate
                .evidence
                .iter()
                .any(|(reference, _)| reference == fields.current_record)
                && candidate
                    .evidence
                    .iter()
                    .any(|(reference, _)| reference == fields.current_model)
        });
        if owners.next().map(|(candidate, _)| candidate) != Some(id) || owners.next().is_some() {
            return Err(refused());
        }
        Ok(())
    }

    // Both entry points use the same actual prior-original model and immutable
    // restoration fields; their independently owned prospective banks coincide.
    pub(super) fn quote_current_checkpoint17_fields_data<'previous>(
        &self,
        previous: &'previous Envelope,
        fields: CheckpointFields17<'_>,
        maximum: usize,
    ) -> Result<NativeObservation17CheckpointStorageData<'previous>, ProviderError> {
        self.authenticate_current_checkpoint17_fields_data(previous, fields)?;
        let model = if fields.capture {
            self.capture17_model_storage_data(previous, maximum)?
        } else {
            self.observation17_model_storage_data(previous, maximum)?
        };
        let restored =
            self.project_observation17_restored_data(previous, fields.current_record, maximum)?;
        let copied = self.observation17_receipt_backing_data(previous, fields.scope)?;
        let retained = sum(&[
            size_of::<NativeObservation17CheckpointAttempt>(),
            size_of::<NativeObservation17CheckpointStorageData<'static>>(),
            model.maximum_encoded_bytes,
            restored.maximum_encoded_bytes,
            multiply(2, copied)?,
            size_of::<PacketNative5Record>(),
            size_of::<PacketNativeRestoredRecord>(),
            multiply(2, "source-owned.packet-receipt/5".len())?,
            "source-owned.packet-restored-native/12".len(),
            // Each independently computed model identity lives in its receipt.
            multiply(
                2,
                "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len(),
            )?,
        ])?;
        let transient = sum(&[
            model.requested_total()?,
            restored.requested_total()?,
            projection_geometry::owner_binding_work_data(
                self.selection
                    .realization
                    .owner_bindings
                    .first()
                    .ok_or_else(refused)?,
                maximum,
            )?
            .requested_total()?,
            projection_geometry::original_work_data(previous, maximum)?.requested_total()?,
            "blake3-256".len() + "cnp.request.v1".len() + 64,
        ])?;
        Ok(NativeObservation17CheckpointStorageData {
            owner: Rc::clone(&self.capture_identity),
            previous,
            row: quote_row(
                retained,
                transient,
                if fields.capture {
                    capture17_checkpoint_counter_scratch_data()
                } else {
                    observation17_producer_counter_scratch_data()
                },
                maximum,
            )?,
            model,
            restored,
        })
    }

    // Keep the destination before any formatter, hash or content comparison can
    // fail. The caller's prior-owner loan spans the complete funded operation.
    pub(super) fn authenticate_current_checkpoint17_into_data(
        &self,
        previous: &Envelope,
        fields: CheckpointFields17<'_>,
        storage: &NativeObservation17CheckpointStorageData<'_>,
        destination: &mut Option<NativeObservation17CheckpointAttempt>,
    ) -> Result<(), ProviderError> {
        if destination.is_some()
            || !Rc::ptr_eq(&storage.owner, &self.capture_identity)
            || !std::ptr::eq(storage.previous, previous)
        {
            return Err(refused());
        }
        self.authenticate_current_checkpoint17_fields_data(previous, fields)?;
        *destination = Some(NativeObservation17CheckpointAttempt {
            model_bytes: Vec::new(),
            receipt: None,
            restored: None,
            restored_bytes: Vec::new(),
            validated: false,
        });
        let attempt = destination.as_mut().ok_or_else(refused)?;
        let cached = self
            .originals
            .get(previous.request_id.0.as_ref().ok_or_else(refused)?)
            .ok_or_else(refused)?;
        if cached.0 != previous.request_hash(crate::envelope::RequestOrigin::Controller)? {
            return Err(refused());
        }
        attempt
            .model_bytes
            .try_reserve_exact(storage.model.maximum_encoded_bytes)
            .map_err(|_| exhausted())?;
        if fields.capture {
            self.encode_capture17_model_data(previous, &storage.model, &mut attempt.model_bytes)?;
        } else {
            let NativeProgram::Connected(program) = &self.program else {
                return Err(refused());
            };
            let inventory = program
                .borrow_original_observation17_inventory_data(&mut MetadataObserver::new())?;
            encode_original_precharged_serialization_into(
                &BorrowedReactiveObservation17 {
                    schema: "source-owned.packet-native/4",
                    native_pid: U64::new(u64::from(self.capture_creator)),
                    original: previous,
                    inventory,
                    grant: None,
                },
                &storage.model,
                &mut attempt.model_bytes,
            )?;
        }
        fields.current_model.verify(&attempt.model_bytes)?;
        if self.content.get(fields.current_model).map(Vec::as_slice)
            != Some(attempt.model_bytes.as_slice())
        {
            return Err(refused());
        }
        attempt.receipt =
            Some(self.original_complete_receipt_data(previous, reference(&attempt.model_bytes)?)?);
        attempt.restored = Some(
            self.complete_restored_evidence
                .as_ref()
                .ok_or_else(refused)?
                .wrap(attempt.receipt.as_ref().ok_or_else(refused)?.clone(), false)?,
        );
        attempt
            .restored_bytes
            .try_reserve_exact(storage.restored.maximum_encoded_bytes)
            .map_err(|_| exhausted())?;
        encode_original_precharged_serialization_into(
            attempt.restored.as_ref().ok_or_else(refused)?,
            &storage.restored,
            &mut attempt.restored_bytes,
        )?;
        fields.current_record.verify(&attempt.restored_bytes)?;
        if self.content.get(fields.current_record).map(Vec::as_slice)
            != Some(attempt.restored_bytes.as_slice())
        {
            return Err(refused());
        }
        self.authenticate_current_checkpoint17_fields_data(previous, fields)?;
        attempt.validated = true;
        Ok(())
    }
}

/// Names actual defining comparison views before its noallocation quote walk.
pub(crate) fn capture17_checkpoint_counter_scratch_data() -> usize {
    observation17_producer_counter_scratch_data() + capture_model17::counter_scratch_data()
}

/// Counts new borrowed views independently of the defining existing controls.
pub(super) const fn field_counter_scratch_data() -> usize {
    size_of::<CheckpointFields17<'static>>()
        + size_of::<&PacketRestoredSettledCaptureRequest>()
        + size_of::<&PacketRestoredInputReactive17Request>()
        + size_of::<Result<NativeObservation17CheckpointStorageData<'static>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Position>()
        + size_of::<Result<Position, ProviderError>>()
}

#[path = "capture_current17/model.rs"]
mod capture_model17;
