//! Binds continuation to the real completed native seed and immediate predecessor.
//!
//! The actual private bank, Source key, published ordinary literals and current
//! receiver poststate remain separate conjuncts. A digest, transfer ID, offset,
//! row or historical DTO cannot create this same-occurrence loan.

use super::*;
use crate::reference_packet::service::native_startup::{
    NativeCapture17PhaseData, NativeRestoredSettledCaptureUploadAttempt,
    original_restored_settled_capture_negotiated_geometry_counter_scratch_data,
};
use crate::reference_packet::service::restored_settled_capture::upload::{
    PacketRestoredSettledCaptureUploadContext, PacketRestoredSettledCaptureUploadOrdinal,
};

/// Keeps real shared occurrences after dropping the immutable Boot bank loan.
pub(in super::super) struct NativeCapture17UploadContinuation {
    seed: Rc<RefCell<NativeRestoredSettledActionAttempt>>,
    seed_index: usize,
    previous: Rc<RefCell<NativeRestoredSettledActionAttempt>>,
    previous_index: usize,
    current_index: usize,
}

impl OriginalNativeCapture17Read {
    /// Verifies the current Chunk/Finish against actual completed seed custody.
    ///
    /// A valid Source-authenticated seed permits only its finite addressed Blob
    /// transfer. Its digest does not authenticate arbitrary new action rights.
    /// Every native phase still requires its own complete independent debit.
    ///
    /// # Errors
    /// Refuses another method, reused read, failed/inflight predecessor, changed
    /// actual receiver, Source proof, current literal, exact grid or ancestry.
    pub(crate) fn authenticate_upload_continuation17_source_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        receiver: &BlobReceiver,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        self.authenticate_slot_data(connection)?;
        if self.source_started.replace(true) || !self.receiving.get() || !self.raw.get() {
            return Err(refused());
        }
        let fixed = native_capture17_upload_continuation_counter_scratch_data();
        let plan = {
            let owner = self.boot.try_borrow().map_err(|_| refused())?;
            owner.ensure_origin()?;
            let reserve = owner.restored_settled.as_ref().ok_or_else(refused)?;
            reserve.authenticate_action_counter_scratch_data(
                &self.boot,
                self.index,
                &self.attempt,
                fixed,
            )?;
            let key: &[u8; 32] = owner
                .data
                .private_key
                .as_slice()
                .try_into()
                .map_err(|_| refused())?;
            reserve.with_capture17_upload_predecessors_data(
                &self.boot,
                self.index,
                &self.attempt,
                |prior| {
                    self.inspect_upload_continuation17_data(
                        connection, receiver, records, key, prior,
                    )
                },
            )?
        };
        // The immutable bank/key loans are gone. The actual native first proof
        // still binds the same World/scope before a Source-bearing bit is set.
        NativeAckBoot::with_original_capture17_ancestry_data(
            &self.boot,
            connection,
            control,
            records,
            |scope, first_original, first_terminal| {
                plan.with_seed17_data(|seed, _| {
                    let NativeCapture17PhaseData::UploadBegin { artifact, .. } =
                        seed.phase17_data()?
                    else {
                        return Err(refused());
                    };
                    if &artifact.request.capture.scope != scope {
                        return Err(refused());
                    }
                    control.authenticate_capture17_first_checkpoint_data(
                        first_original,
                        first_terminal,
                        &artifact.request.capture.first_observation,
                    )
                })
            },
        )?;
        self.authenticate_slot_data(connection)?;
        *self
            .upload_continuation
            .try_borrow_mut()
            .map_err(|_| refused())? = Some(plan);
        self.source_verified.set(true);
        Ok(())
    }

    fn inspect_upload_continuation17_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        receiver: &BlobReceiver,
        records: &[ExchangeRecord],
        key: &[u8; 32],
        prior: &[Rc<RefCell<NativeRestoredSettledActionAttempt>>],
    ) -> Result<NativeCapture17UploadContinuation, ProviderError> {
        connection.authenticate_native_capture17_upload_receiver_data(receiver)?;
        let current = self.attempt.try_borrow().map_err(|_| refused())?;
        let current = current.capture_upload17_data()?;
        let original = current.original_data()?;
        connection.authenticate_original_native_capture17_literal_data(
            original,
            self.incoming_slot.get().ok_or_else(refused)?,
        )?;
        connection.authenticate_native_capture17_incoming_data(original)?;
        let continuation = match current.phase17_data()? {
            NativeCapture17PhaseData::Chunk { continuation, .. }
            | NativeCapture17PhaseData::Finish { continuation, .. } => continuation,
            _ => return Err(refused()),
        };
        continuation.validate_data()?;
        let previous_index = prior.len().checked_sub(1).ok_or_else(refused)?;
        let previous_owner = prior.get(previous_index).ok_or_else(refused)?;
        let previous = previous_owner.try_borrow().map_err(|_| refused())?;
        let previous_child = previous.capture_upload17_data()?;
        let previous = previous_child.published_upload17_data()?;
        previous.authenticate_current_receiver_data(receiver)?;
        let progress = previous.progress_data().ok_or_else(refused)?;
        let record = records
            .get(previous.publication_record_data())
            .ok_or_else(refused)?;
        record.authenticate_capture17_upload_predecessor_data(
            connection,
            previous.original_data(),
            previous.terminal_data(),
            original,
        )?;
        let mut seed_index = None;
        for (index, candidate_owner) in prior.iter().enumerate().rev() {
            let candidate = candidate_owner.try_borrow().map_err(|_| refused())?;
            let candidate = candidate.capture_upload17_data()?;
            let published = candidate.published_upload17_data()?;
            match published.phase_data() {
                NativeCapture17PhaseData::Chunk {
                    continuation: previous,
                    ..
                } if *previous == continuation => {}
                NativeCapture17PhaseData::UploadBegin {
                    artifact, context, ..
                } => {
                    // This invocation is paid by the current fresh ingress's
                    // defining full-frame digest/MAC transient phases. The
                    // immutable seed's retained row contributes no new credit.
                    candidate.authenticate_retained_upload_source17_data(key, self.frame)?;
                    if published
                        .progress_data()
                        .is_none_or(|progress| progress.next_offset != U64::new(0))
                    {
                        return Err(refused());
                    }
                    if artifact.proof.context_digest.as_slice()
                        != continuation.context_digest.as_slice()
                    {
                        return Err(refused());
                    }
                    validate_current_data(
                        connection,
                        current,
                        context,
                        artifact.proof.context_digest.as_slice(),
                        progress.next_offset,
                    )?;
                    let record = records
                        .get(published.publication_record_data())
                        .ok_or_else(refused)?;
                    record.authenticate_capture17_upload_predecessor_data(
                        connection,
                        published.original_data(),
                        published.terminal_data(),
                        original,
                    )?;
                    seed_index = Some(index);
                    break;
                }
                _ => return Err(refused()),
            }
        }
        let seed_index = seed_index.ok_or_else(refused)?;
        Ok(NativeCapture17UploadContinuation {
            seed: Rc::clone(prior.get(seed_index).ok_or_else(refused)?),
            seed_index,
            previous: Rc::clone(previous_owner),
            previous_index,
            current_index: self.index,
        })
    }
}

fn validate_current_data<S: ProviderStream>(
    connection: &Connection<S>,
    current: &NativeRestoredSettledCaptureUploadAttempt,
    seed: &PacketRestoredSettledCaptureUploadContext,
    digest: &[u8],
    next: U64,
) -> Result<(), ProviderError> {
    let original = current.original_data()?;
    let request = &seed.request;
    let target = &request.capture.scope.target;
    let (body_transfer, continuation) = match current.phase17_data()? {
        NativeCapture17PhaseData::Chunk { body, continuation } => (&body.transfer_id, continuation),
        NativeCapture17PhaseData::Finish { body, continuation } => {
            (&body.transfer_id, continuation)
        }
        _ => return Err(refused()),
    };
    if original.session_id.0.as_ref() != Some(&target.session)
        || original.incarnation_id.0.as_ref() != Some(&target.incarnation)
        || original.node_id.0.as_ref() != Some(&target.node)
        || original.capture_owner_id.0.as_ref() != Some(&request.capture.capture_owner)
        || original.execution_owner_id.0.is_some()
        || original.operation_id.0.is_some()
        || body_transfer != &request.transfer_id
        || continuation.capture_operation != request.capture.capture_operation
        || continuation.transfer_id != request.transfer_id
        || continuation.context_digest.as_slice() != digest
        || digest.len() != 32
    {
        return Err(refused());
    }
    let geometry = connection.quote_current_capture17_upload_geometry_data(
        original,
        &request.capture.history_prefix,
        &request.capture.runtime_object,
    )?;
    let ordinal = match request.ordinal {
        PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => 0,
        PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => 1,
    };
    authenticate_next_phase_data(
        current.phase17_data()?,
        &geometry,
        ordinal,
        request.content.length,
        next,
    )
}

// These exact progression facts are DATA. The actual Scope above supplies its
// genuine seed/previous owners, Source proof and live receiver before using it.
fn authenticate_next_phase_data(
    phase: NativeCapture17PhaseData<'_>,
    geometry: &crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData,
    ordinal: usize,
    content_length: U64,
    next: U64,
) -> Result<(), ProviderError> {
    match phase {
        NativeCapture17PhaseData::Chunk { body, .. } => {
            let offset = usize::try_from(body.offset.get()).map_err(|_| refused())?;
            if body.offset != next
                || body.bytes.as_slice().len()
                    != geometry.expected_chunk_length_data(ordinal, offset)?
            {
                return Err(refused());
            }
        }
        NativeCapture17PhaseData::Finish { .. } if next == content_length => {}
        _ => return Err(refused()),
    }
    Ok(())
}

impl NativeCapture17UploadContinuation {
    fn with_seed17_data<R>(
        &self,
        inspect: impl FnOnce(
            &NativeRestoredSettledCaptureUploadAttempt,
            usize,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        let seed = self.seed.try_borrow().map_err(|_| refused())?;
        let seed = seed.capture_upload17_data()?;
        let _ = seed.published_upload17_data()?;
        inspect(seed, self.seed_index)
    }
}

pub(super) fn native_capture17_upload_continuation_counter_scratch_data() -> usize {
    size_of::<NativeCapture17UploadContinuation>()
        + size_of::<Result<NativeCapture17UploadContinuation, ProviderError>>()
        + size_of::<Ref<'static, Option<NativeCapture17UploadContinuation>>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredSettledActionAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeAckBoot>>()
        + size_of::<Result<Ref<'static, NativeRestoredSettledActionAttempt>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestoredSettledActionAttempt>, std::cell::BorrowMutError>>()
        + size_of::<Ref<'static, NativeRestoredSettledActionAttempt>>() * 3
        + size_of::<Ref<'static, NativeAckBoot>>()
        + size_of::<&[Rc<RefCell<NativeRestoredSettledActionAttempt>>]>()
        + size_of::<std::iter::Rev<std::iter::Enumerate<std::slice::Iter<'static, Rc<RefCell<NativeRestoredSettledActionAttempt>>>>>>()
        + size_of::<Option<usize>>()
        + size_of::<NativeCapture17PhaseData<'static>>()
        + size_of::<&crate::reference_packet::service::native_startup::PacketRestoredSettledCaptureUploadGeometryData>()
        + size_of::<usize>()
        + size_of::<U64>() * 2
        + size_of::<&[u8; 32]>()
        + size_of::<Result<&[u8; 32], std::array::TryFromSliceError>>()
        + size_of::<Result<(), ProviderError>>()
        // The immediately preceding published loan stays live while each
        // candidate constructs and verifies a separate historical loan.
        + NativeRestoredSettledCaptureUploadAttempt::published_upload17_counter_scratch_data()
        + NativeRestoredSettledCaptureUploadAttempt::published_upload17_counter_scratch_data()
        + NativeRestoredSettledCaptureUploadAttempt::continuation_upload17_counter_scratch_data()
        + original_restored_settled_capture_negotiated_geometry_counter_scratch_data()
        + crate::reference_packet::service::restored_settled_capture::upload::restored_settled_capture_upload_counter_scratch_data()
        + Connection::<DeadlineStream>::capture17_upload_correspondence_counter_scratch_data()
        + crate::connection::original_native17_publication_literal_counter_scratch_data()
}

impl OriginalNativeCapture17Read {
    /// Selects only the actual authenticated assigned or continuation upload path.
    ///
    /// # Errors
    /// Refuses another real method, absent seed ownership or any complete phase
    /// quotation/native debit failure. This method does not select public IO.
    pub(crate) fn prepare_current_upload17_data(
        &self,
        connection: &Connection<DeadlineStream>,
        receiver: &BlobReceiver,
        control: &PacketControl,
        records: &Vec<ExchangeRecord>,
        first_outgoing: u64,
    ) -> Result<OriginalPacketPrefixProjectionStorageData<0>, ProviderError> {
        let method = self.original_data()?.method;
        match method {
            Method::BlobBegin => self.prepare_assigned_upload17_data(
                connection,
                receiver,
                control,
                records,
                first_outgoing,
            ),
            Method::BlobChunk | Method::BlobFinish => self.prepare_continuation_upload17_data(
                connection,
                receiver,
                control,
                records,
                first_outgoing,
            ),
            _ => Err(refused()),
        }
    }

    fn prepare_continuation_upload17_data(
        &self,
        connection: &Connection<DeadlineStream>,
        receiver: &BlobReceiver,
        control: &PacketControl,
        records: &Vec<ExchangeRecord>,
        first_outgoing: u64,
    ) -> Result<OriginalPacketPrefixProjectionStorageData<0>, ProviderError> {
        if self.upload_preparing.replace(true) || self.upload_action_started.get() {
            return Err(refused());
        }
        self.authenticate_slot_data(connection)?;
        self.authenticate_private_upload_slot_data()?;
        let fixed = native_capture17_upload_scope_counter_scratch_data();
        {
            let owner = self.boot.try_borrow().map_err(|_| refused())?;
            owner
                .restored_settled
                .as_ref()
                .ok_or_else(refused)?
                .authenticate_action_counter_scratch_data(
                    &self.boot,
                    self.index,
                    &self.attempt,
                    fixed,
                )?;
        }
        connection.authenticate_native_capture17_upload_receiver_data(receiver)?;
        NativeAckBoot::authenticate_original_observation17_ancestry_data(
            &self.boot, connection, control, records,
        )?;
        let plan = self
            .upload_continuation
            .try_borrow()
            .map_err(|_| refused())?;
        let plan = plan.as_ref().ok_or_else(refused)?;
        plan.authenticate_same_native_parents_data(self)?;
        plan.with_seed17_data(|seed, _| {
            let NativeCapture17PhaseData::UploadBegin {
                artifact, context, ..
            } = seed.phase17_data()?
            else {
                return Err(refused());
            };
            let previous = plan.previous.try_borrow().map_err(|_| refused())?;
            previous
                .capture_upload17_data()?
                .published_upload17_data()?
                .authenticate_current_receiver_data(receiver)?;
            let mut current = self.attempt.try_borrow_mut().map_err(|_| refused())?;
            let current = current.capture_upload17_data_mut()?;
            let (original, input, signed) = current.continuation_upload17_quote_parts_data(
                context,
                artifact.proof.context_digest.as_slice(),
            )?;
            if signed.declared_counter_scratch_bytes.get() < quantity(fixed)?.get() {
                return Err(exhausted());
            }
            connection.authenticate_original_native_capture17_literal_data(
                original,
                self.incoming_slot.get().ok_or_else(refused)?,
            )?;
            connection.authenticate_native_capture17_incoming_data(original)?;
            let maximum =
                usize::try_from(signed.requested_peak_data()?).map_err(|_| exhausted())?;
            let storage = receiver.quote_capture17_upload_storage_data(input, maximum)?;
            let original_shape = project_original_data(original, maximum)?;
            let terminal_shape =
                project_terminal_data(receiver, &storage, input, original, maximum)?;
            let prefix = connection
                .quote_original_capture17_upload_prefix_projection_storage_data(
                    first_outgoing,
                    original,
                    OriginalPacketPrefixProjectionInput {
                        terminal: &terminal_shape,
                        original: &original_shape,
                        objects: &[],
                        maximum_requested_bytes: maximum,
                    },
                )?;
            let mut transport = prefix.capture17_upload_transport_storage_data()?;
            if records.len() == records.capacity() {
                let replacement = records
                    .len()
                    .checked_add(1)
                    .and_then(|target| target.checked_mul(size_of::<ExchangeRecord>()))
                    .ok_or_else(exhausted)?;
                transport.retained_requested_bytes = transport
                    .retained_requested_bytes
                    .checked_add(quantity(replacement)?)?;
            }
            let row = combined_row(
                storage.row_data(),
                transport,
                terminal_shape.retained_value_backing_bytes,
                storage.reply_storage_data().retained_value_backing_bytes,
                fixed,
            )?;
            signed.authenticate_actual_data(&row)?;
            {
                let mut owner = self.boot.try_borrow_mut().map_err(|_| refused())?;
                owner
                    .restored_settled
                    .as_mut()
                    .ok_or_else(refused)?
                    .begin_action_data(&self.boot, self.index, row)?;
            }
            self.upload_action_started.set(true);
            *self
                .upload_storage
                .try_borrow_mut()
                .map_err(|_| refused())? = Some(storage.duplicate_correspondence_data());
            current.install_continuation_upload17_action_data(
                storage,
                row,
                context,
                artifact.proof.context_digest.as_slice(),
            )?;
            Ok(prefix)
        })
    }

    /// Executes the actual selected upload through its already spent private token.
    ///
    /// # Errors
    /// Refuses another method, missing source/seed/native custody, a repeated
    /// execution or any real primitive/reply failure, retaining all partials.
    pub(crate) fn execute_current_upload17_data(
        &self,
        receiver: &mut BlobReceiver,
    ) -> Result<(), ProviderError> {
        let method = self.original_data()?.method;
        match method {
            Method::BlobBegin => self.execute_assigned_upload17_data(receiver),
            Method::BlobChunk | Method::BlobFinish => {
                self.authenticate_private_upload_slot_data()?;
                if !self.upload_action_started.get() {
                    return Err(refused());
                }
                self.upload_continuation
                    .try_borrow()
                    .map_err(|_| refused())?
                    .as_ref()
                    .ok_or_else(refused)?
                    .authenticate_same_native_parents_data(self)?;
                self.attempt
                    .try_borrow_mut()
                    .map_err(|_| refused())?
                    .capture_upload17_data_mut()?
                    .execute_continuation_upload17_data(receiver, self)?;
                self.authenticate_private_upload_slot_data()
            }
            _ => Err(refused()),
        }
    }
}

impl NativeCapture17UploadContinuation {
    fn authenticate_same_native_parents_data(
        &self,
        scope: &OriginalNativeCapture17Read,
    ) -> Result<(), ProviderError> {
        if self.current_index != scope.index
            || self.previous_index.checked_add(1) != Some(scope.index)
        {
            return Err(refused());
        }
        let owner = scope.boot.try_borrow().map_err(|_| refused())?;
        owner
            .restored_settled
            .as_ref()
            .ok_or_else(refused)?
            .with_capture17_upload_predecessors_data(
                &scope.boot,
                scope.index,
                &scope.attempt,
                |prior| {
                    if prior
                        .get(self.seed_index)
                        .is_none_or(|actual| !Rc::ptr_eq(actual, &self.seed))
                        || prior
                            .get(self.previous_index)
                            .is_none_or(|actual| !Rc::ptr_eq(actual, &self.previous))
                    {
                        return Err(refused());
                    }
                    Ok(())
                },
            )
    }
}

#[cfg(test)]
#[path = "continuation17_tests.rs"]
mod tests;
