//! Spends two separately signed upload ordinals before actual content effects.
//!
//! The genuine boot retains each Begin and every unfinished request. An ordinal
//! cannot be retried or selected by an artifact label; coordinator completion
//! precedes the manifest ordinal. A separately admitted exact raw bank retains
//! these two inert objects. The existing Control content ledger still enforces
//! its object and total limits; full model validation precedes activation.

use super::*;
use crate::bodies::RequestBody;
use crate::reference_packet::service::complete_restore::activation::upload::*;
use crucible_node_format::Validate;

pub(crate) struct NativeRestorationUploadAttempt {
    creator: u32,
    thread: ThreadId,
    ordinal: usize,
    original: Option<Envelope>,
    artifact: Option<PacketRestorationActivationUploadArtifact>,
    context: Option<PacketRestorationActivationUploadContext>,
    pending: Option<Envelope>,
    terminal: Option<Envelope>,
    seen: Vec<Id>,
    bytes: Vec<u8>,
    content_attempted: bool,
    next_offset: usize,
    published_requests: usize,
    verified: bool,
    begun: bool,
    complete: bool,
    next_progress: Option<(usize, bool)>,
}

pub(crate) struct OriginalRestorationUploadPermit {
    boot: Rc<RefCell<NativeAckBoot>>,
    attempt: Rc<RefCell<NativeRestorationUploadAttempt>>,
    authority: ConnectionAuthority,
}

impl NativeAckBoot {
    pub(crate) fn has_completed_restoration_for_activation_data(
        &self,
    ) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        Ok(self.restoration.is_some())
    }

    pub(crate) fn retain_restoration_upload<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        original: Envelope,
        control: &PacketControl,
    ) -> Result<OriginalRestorationUploadPermit, ProviderError> {
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        if !Rc::ptr_eq(boot, &admission.boot) {
            return Err(refused());
        }
        let mut owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        if !owner.requires_restoration_activation_data()? {
            return Err(refused());
        }
        owner
            .startup
            .as_ref()
            .ok_or_else(refused)?
            .allocation
            .native_birth
            .authenticate_actual_data(&original_native_restoration_activation_ingress_row_data(
                usize::try_from(admission.authority.limits().frame_bytes.get())
                    .map_err(|_| refused())?,
            )?)?;
        let commit = owner
            .restoration
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        control.authenticate_original_restoration_activation_hold_data(
            commit.physical_hold.as_ref().ok_or_else(refused)?,
        )?;
        drop(commit);
        let arm = owner.restoration_activation[0]
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        arm.ensure_origin()?;
        if !arm.verified || !arm.dispatched || !arm.published {
            return Err(refused());
        }
        drop(arm);

        let begin = original.method == crate::envelope::Method::BlobBegin;
        let ordinal = match owner.restoration_uploads[0].as_ref() {
            None if begin => 0,
            Some(first) if first.try_borrow().map_err(|_| borrowed())?.complete => 1,
            Some(_) if !begin => 0,
            _ => return Err(refused()),
        };
        if ordinal == 1 && !begin && owner.restoration_uploads[1].is_none() {
            return Err(refused());
        }
        let attempt = if begin {
            if owner.restoration_uploads[ordinal].is_some() {
                return Err(refused());
            }
            let attempt = Rc::new(RefCell::new(NativeRestorationUploadAttempt {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                ordinal,
                original: Some(original),
                artifact: None,
                context: None,
                pending: None,
                terminal: None,
                seen: Vec::new(),
                bytes: Vec::new(),
                content_attempted: false,
                next_offset: 0,
                published_requests: 0,
                verified: false,
                begun: false,
                complete: false,
                next_progress: None,
            }));
            owner.restoration_uploads[ordinal] = Some(Rc::clone(&attempt));
            attempt
        } else {
            let attempt = Rc::clone(
                owner.restoration_uploads[ordinal]
                    .as_ref()
                    .ok_or_else(refused)?,
            );
            {
                let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
                flight.ensure_origin()?;
                if !flight.verified
                    || !flight.begun
                    || flight.complete
                    || flight.pending.is_some()
                    || flight.next_progress.is_some()
                {
                    return Err(refused());
                }
                flight.pending = Some(original);
            }
            attempt
        };
        drop(owner);
        let permit = OriginalRestorationUploadPermit {
            boot: Rc::clone(boot),
            attempt,
            authority: admission.authority.clone(),
        };
        if begin {
            permit.verify_begin(connection)?;
        }
        permit.authenticate_next(connection)?;
        Ok(permit)
    }

    pub(super) fn authenticate_restoration_activation_uploads_data(
        &self,
        scope: &PacketRestorationActivationScope,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        let first = self.restoration_uploads[0]
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        let second = self.restoration_uploads[1]
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        for (ordinal, flight) in [(0, &*first), (1, &*second)] {
            flight.ensure_origin()?;
            let request = &flight.artifact.as_ref().ok_or_else(refused)?.request;
            if !flight.complete
                || flight.pending.is_some()
                || flight.ordinal != ordinal
                || request.scope != *scope
                || flight.terminal.is_none()
            {
                return Err(refused());
            }
        }
        let first = &first.artifact.as_ref().ok_or_else(refused)?.request;
        let second = &second.artifact.as_ref().ok_or_else(refused)?.request;
        if first.coordinator != second.coordinator || first.manifest != second.manifest {
            return Err(refused());
        }
        let actual = ContentRef::deserialize(
            original
                .body
                .get("activation_manifest")
                .ok_or_else(refused)?,
        )
        .map_err(ContractError::from)?;
        if actual != first.manifest {
            return Err(refused());
        }
        Ok(())
    }
}

impl OriginalRestorationUploadPermit {
    fn verify_begin<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        {
            let artifact = {
                let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
                let value = flight
                    .original
                    .as_ref()
                    .ok_or_else(refused)?
                    .extensions
                    .get(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
                    .ok_or_else(refused)?;
                crate::connection::serialized_credit(
                    value,
                    MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
                )?;
                PacketRestorationActivationUploadArtifact::deserialize(value)
                    .map_err(ContractError::from)?
            };
            self.attempt
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .artifact = Some(artifact);
        }
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        let policy = owner.policy.as_ref().ok_or_else(refused)?;
        authenticate_restoration_activation_upload_selection_data(
            policy.original_restoration_activation_selection_data(),
            &self.authority,
        )?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
        artifact.validate_data()?;
        if artifact.request.role.ordinal_data() != flight.ordinal {
            return Err(refused());
        }
        authenticate_scope(&owner, connection, &artifact.request.scope)?;
        let original = flight.original.as_ref().ok_or_else(refused)?;
        let request = &artifact.request;
        authenticate_upload_envelope(original, request, &self.authority)?;
        if request.maximum_frame_bytes != self.authority.limits().frame_bytes
            || request.chunk_bytes > self.authority.limits().blob_chunk_bytes
        {
            return Err(refused());
        }
        let maximum_object = match request.role {
            PacketRestorationActivationUploadRole::Coordinator => {
                crate::reference_packet::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES
            }
            PacketRestorationActivationUploadRole::Manifest => {
                MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES
            }
        };
        let length =
            usize::try_from(request.content_ref_data().length.get()).map_err(|_| refused())?;
        if length == 0 || length > maximum_object {
            return Err(refused());
        }
        let assigned = restoration_activation_upload_assigned_request_digest(
            original,
            request.role,
            usize::try_from(request.maximum_frame_bytes.get()).map_err(|_| refused())?,
        )?;
        let context = PacketRestorationActivationUploadContext {
            request: request.clone(),
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        flight.context = Some(context);
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        verify_restoration_activation_upload_proof_data(
            key,
            flight.context.as_ref().ok_or_else(refused)?,
            &flight.artifact.as_ref().ok_or_else(refused)?.proof,
        )?;
        let request = &flight.artifact.as_ref().ok_or_else(refused)?.request;
        let required =
            original_native_restoration_activation_upload_required_storage_data(request)?;
        authenticate_row(&request.native_allocation, &required)?;
        if flight.ordinal == 1 {
            let prior = owner.restoration_uploads[0]
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| borrowed())?;
            prior.ensure_origin()?;
            let prior_request = &prior.artifact.as_ref().ok_or_else(refused)?.request;
            let request = &flight.artifact.as_ref().ok_or_else(refused)?.request;
            if !prior.complete
                || prior_request.scope != request.scope
                || prior_request.coordinator != request.coordinator
                || prior_request.manifest != request.manifest
            {
                return Err(refused());
            }
            let prior_begin = crate::bodies::decode_request(
                crate::envelope::Method::BlobBegin,
                &prior.original.as_ref().ok_or_else(refused)?.body,
            )?;
            let current_begin = crate::bodies::decode_request(
                crate::envelope::Method::BlobBegin,
                &flight.original.as_ref().ok_or_else(refused)?.body,
            )?;
            match (prior_begin, current_begin) {
                (RequestBody::BlobBegin(prior), RequestBody::BlobBegin(current))
                    if prior.transfer_id != current.transfer_id => {}
                _ => return Err(refused()),
            }
        }
        let count = usize::try_from(
            flight
                .artifact
                .as_ref()
                .ok_or_else(refused)?
                .request
                .maximum_requests
                .get(),
        )
        .map_err(|_| refused())?;
        flight.seen.try_reserve_exact(count).map_err(|_| {
            ProviderError::ResourceExhausted("native activation upload request IDs")
        })?;
        if flight.seen.capacity() != count {
            return Err(refused());
        }
        // Only the authenticated independent native row can fund this raw
        // bank. It remains in the once slot after Finish and on every failure.
        let length = usize::try_from(
            flight
                .artifact
                .as_ref()
                .ok_or_else(refused)?
                .request
                .content_ref_data()
                .length
                .get(),
        )
        .map_err(|_| refused())?;
        flight
            .bytes
            .try_reserve_exact(length)
            .map_err(|_| ProviderError::ResourceExhausted("native selected upload content bank"))?;
        if flight.bytes.capacity() != length {
            return Err(refused());
        }
        flight.verified = true;
        Ok(())
    }

    fn authenticate_next<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified || flight.complete || flight.next_progress.is_some() {
            return Err(refused());
        }
        let request = &flight.artifact.as_ref().ok_or_else(refused)?.request;
        authenticate_scope(&owner, connection, &request.scope)?;
        let original = if flight.begun {
            flight.pending.as_ref()
        } else {
            flight.original.as_ref()
        }
        .ok_or_else(refused)?;
        if original.message != crate::envelope::MessageKind::Request
            || original.session_id.0.as_ref() != Some(self.authority.session_id())
            || original.incarnation_id.0.as_ref() != Some(self.authority.incarnation_id())
            || original.node_id.0.as_ref() != Some(&request.scope.target.node)
            || original.execution_owner_id.0.as_ref() != Some(&request.scope.target.owner)
            || original.operation_id.0.is_some()
            || original.capture_owner_id.0.is_some()
        {
            return Err(refused());
        }
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        if flight.seen.iter().any(|old| old == id)
            || flight.seen.len() >= flight.seen.capacity()
            || flight.published_requests
                >= usize::try_from(request.maximum_requests.get()).map_err(|_| refused())?
        {
            return Err(refused());
        }
        let begin = match crate::bodies::decode_request(
            crate::envelope::Method::BlobBegin,
            &flight.original.as_ref().ok_or_else(refused)?.body,
        )? {
            RequestBody::BlobBegin(begin) => begin,
            _ => return Err(refused()),
        };
        let length =
            usize::try_from(request.content_ref_data().length.get()).map_err(|_| refused())?;
        let progress = match crate::bodies::decode_request(original.method, &original.body)? {
            RequestBody::BlobBegin(actual) if !flight.begun => {
                if actual.transfer_id != begin.transfer_id
                    || actual.content != *request.content_ref_data()
                    || !actual.extensions.is_empty()
                {
                    return Err(refused());
                }
                (0, false)
            }
            RequestBody::BlobChunk(chunk) if flight.begun => {
                let expected = length
                    .checked_sub(flight.next_offset)
                    .ok_or_else(refused)?
                    .min(usize::try_from(request.chunk_bytes.get()).map_err(|_| refused())?);
                if !original.extensions.is_empty()
                    || chunk.transfer_id != begin.transfer_id
                    || chunk.offset.get()
                        != u64::try_from(flight.next_offset).map_err(|_| refused())?
                    || chunk.bytes.as_slice().len() != expected
                    || expected == 0
                    || !chunk.extensions.is_empty()
                {
                    return Err(refused());
                }
                (
                    flight
                        .next_offset
                        .checked_add(expected)
                        .ok_or_else(refused)?,
                    false,
                )
            }
            RequestBody::BlobFinish(finish) if flight.begun => {
                if !original.extensions.is_empty()
                    || finish.transfer_id != begin.transfer_id
                    || flight.next_offset != length
                    || !finish.extensions.is_empty()
                {
                    return Err(refused());
                }
                (length, true)
            }
            _ => return Err(refused()),
        };
        let id = id.clone();
        flight.seen.push(id);
        flight.next_progress = Some(progress);
        Ok(())
    }

    /// Mutates only the exact inert content bank covered by this spent permit.
    ///
    /// # Errors
    /// Refuses a repeated effect, conflicting raw length/hash, or exhausted
    /// unchanged Control content credit. Partial banks remain in the once slot.
    pub(crate) fn prepare_content_reply_data(
        &self,
        control: &mut PacketControl,
    ) -> Result<crate::reference_packet::control::PacketControlReply, ProviderError> {
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified
            || flight.complete
            || flight.content_attempted
            || flight.next_progress.is_none()
        {
            return Err(refused());
        }
        flight.content_attempted = true;

        let NativeRestorationUploadAttempt {
            original,
            pending,
            begun,
            artifact,
            bytes,
            ..
        } = &mut *flight;
        let envelope = if *begun {
            pending.as_ref()
        } else {
            original.as_ref()
        }
        .ok_or_else(refused)?;
        let request = &artifact.as_ref().ok_or_else(refused)?.request;
        let body = crate::bodies::decode_request(envelope.method, &envelope.body)?;
        let result = match body {
            RequestBody::BlobBegin(begin) => {
                if !bytes.is_empty() {
                    return Err(refused());
                }
                completed_upload_result(crate::bodies::BlobBeginResult {
                    transfer_id: begin.transfer_id,
                    next_offset: U64::new(0),
                    maximum_chunk_bytes: request.chunk_bytes,
                })?
            }
            RequestBody::BlobChunk(chunk) => {
                let next = append_upload_chunk_data(bytes, chunk.offset, chunk.bytes.as_slice())?;
                completed_upload_result(crate::bodies::BlobChunkResult {
                    transfer_id: chunk.transfer_id,
                    next_offset: u64::try_from(next).map(U64::new).map_err(|_| refused())?,
                })?
            }
            RequestBody::BlobFinish(finish) => {
                let content = request.content_ref_data();
                content.verify(bytes)?;
                // This is inert possession of the two exact signed references.
                // Full coordinator/manifest semantics run under the independent
                // World row before any proof or physical release.
                control.install_original_restoration_upload_content_data(content.clone(), bytes)?;
                completed_upload_result(crate::bodies::BlobFinishResult {
                    transfer_id: finish.transfer_id,
                    content: content.clone(),
                })?
            }
            _ => return Err(refused()),
        };
        Ok(crate::reference_packet::control::PacketControlReply {
            body: result,
            evidence: Vec::new(),
        })
    }

    pub(crate) fn original_data(&self) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        std::cell::Ref::filter_map(flight, |flight| {
            if flight.begun {
                flight.pending.as_ref()
            } else {
                flight.original.as_ref()
            }
        })
        .map_err(|_| refused())
    }

    pub(crate) fn complete_publication<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        record: &crate::connection::ExchangeRecord,
    ) -> Result<(), ProviderError> {
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        let request = &flight.artifact.as_ref().ok_or_else(refused)?.request;
        authenticate_scope(&owner, connection, &request.scope)?;
        if record.sent() != record.originals().len() {
            return Err(refused());
        }
        let terminal = record.originals().last().ok_or_else(refused)?;
        let original = if flight.begun {
            flight.pending.as_ref()
        } else {
            flight.original.as_ref()
        }
        .ok_or_else(refused)?;
        if terminal.message != crate::envelope::MessageKind::Response
            || terminal.method != original.method
            || terminal.request_id != original.request_id
            || terminal.session_id != original.session_id
            || terminal.incarnation_id != original.incarnation_id
        {
            return Err(refused());
        }
        let response = crate::bodies::decode_response(
            &crate::bodies::decode_request(original.method, &original.body)?,
            &terminal.body,
        )?;
        if !matches!(
            response.shape,
            crate::bodies::ResponseShape::Completed { .. }
        ) {
            return Err(refused());
        }
        let begin = match crate::bodies::decode_request(
            crate::envelope::Method::BlobBegin,
            &flight.original.as_ref().ok_or_else(refused)?.body,
        )? {
            RequestBody::BlobBegin(begin) => begin,
            _ => return Err(refused()),
        };
        let (offset, complete) = flight.next_progress.ok_or_else(refused)?;
        let agrees = match response.result.as_ref() {
            Some(crate::bodies::MethodResult::BlobBegin(result)) => {
                !flight.begun
                    && result.transfer_id == begin.transfer_id
                    && result.next_offset.get() == 0
                    && result.maximum_chunk_bytes == request.chunk_bytes
            }
            Some(crate::bodies::MethodResult::BlobChunk(result)) => {
                original.method == crate::envelope::Method::BlobChunk
                    && result.transfer_id == begin.transfer_id
                    && result.next_offset.get() == u64::try_from(offset).map_err(|_| refused())?
            }
            Some(crate::bodies::MethodResult::BlobFinish(result)) => {
                original.method == crate::envelope::Method::BlobFinish
                    && result.transfer_id == begin.transfer_id
                    && result.content == *request.content_ref_data()
            }
            _ => false,
        };
        if !agrees || !flight.content_attempted {
            return Err(refused());
        }
        let expected_requests =
            usize::try_from(request.maximum_requests.get()).map_err(|_| refused())?;
        let published = flight
            .published_requests
            .checked_add(1)
            .ok_or_else(refused)?;
        if published > expected_requests || (complete && published != expected_requests) {
            return Err(refused());
        }
        flight.terminal = Some(terminal.clone());
        flight.next_offset = offset;
        flight.published_requests = published;
        flight.begun = true;
        flight.complete = complete;
        flight.next_progress = None;
        flight.content_attempted = false;
        // The same completed publication now owns its literal in the endpoint
        // record. Reclaim this temporary parsed request only after that cut.
        flight.pending = None;
        Ok(())
    }
}

fn authenticate_scope<S: ProviderStream>(
    owner: &NativeAckBoot,
    connection: &Connection<S>,
    scope: &PacketRestorationActivationScope,
) -> Result<(), ProviderError> {
    owner.authenticate_original_invocation_prepare_target_data()?;
    let admission = connection.original_native_owned11_admission()?;
    admission.authenticate_current(connection)?;
    if owner
        .policy
        .as_ref()
        .is_none_or(|policy| !Rc::ptr_eq(policy, &admission.policy))
    {
        return Err(refused());
    }
    let commit = owner
        .restoration
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
    commit.ensure_origin()?;
    if !commit.verified
        || !commit.installation_started
        || !commit.receipt_started
        || commit.receipt_body.is_empty()
        || commit.completed_response.is_none()
    {
        return Err(refused());
    }
    connection.authenticate_installed_complete_restoration(&commit.mapping)?;
    commit
        .physical_hold
        .as_ref()
        .ok_or_else(refused)?
        .authenticate_held()?;
    let purpose = owner.authenticate_original_invocation_birth_data()?;
    purpose.authenticate_restoration_source_data(
        &scope.source_runtime,
        &scope.restoration.captured_owner_state,
        &scope.target.owner,
    )?;
    authenticate_completed_commit(owner, &commit, scope)?;
    let arm = owner.restoration_activation[0]
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| borrowed())?;
    arm.ensure_origin()?;
    if !arm.verified
        || !arm.dispatched
        || !arm.published
        || arm.artifact.as_ref().ok_or_else(refused)?.request.scope != *scope
    {
        return Err(refused());
    }
    admission.authority.ensure_live()
}

fn authenticate_upload_envelope(
    original: &Envelope,
    request: &PacketRestorationActivationUploadRequest,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    if original.method != crate::envelope::Method::BlobBegin
        || original.message != crate::envelope::MessageKind::Request
        || original.extensions.len() != 1
        || original.request_id.0.is_none()
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.node_id.0.as_ref() != Some(&request.scope.target.node)
        || original.execution_owner_id.0.as_ref() != Some(&request.scope.target.owner)
        || original.capture_owner_id.0.is_some()
        || original.operation_id.0.is_some()
    {
        return Err(refused());
    }
    let RequestBody::BlobBegin(begin) =
        crate::bodies::decode_request(original.method, &original.body)?
    else {
        return Err(refused());
    };
    begin.validate()?;
    if begin.content != *request.content_ref_data() || !begin.extensions.is_empty() {
        return Err(refused());
    }
    authority.ensure_live()
}

impl NativeRestorationUploadAttempt {
    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

impl NativeAckBoot {
    pub(super) fn authenticate_restoration_uploaded_coordinator_data(
        &self,
        scope: &PacketRestorationActivationScope,
        coordinator: &ContentRef,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        let first = self.restoration_uploads[0]
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| borrowed())?;
        first.ensure_origin()?;
        let request = &first.artifact.as_ref().ok_or_else(refused)?.request;
        if !first.complete || request.scope != *scope || &request.coordinator != coordinator {
            return Err(refused());
        }
        Ok(())
    }
}

pub(crate) fn original_native_restoration_upload_attempt_backing_data()
-> Result<usize, ProviderError> {
    size_of::<RefCell<NativeRestorationUploadAttempt>>()
        .checked_add(
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                std::mem::align_of::<RefCell<NativeRestorationUploadAttempt>>(),
            )?,
        )
        .ok_or_else(refused)
}

pub(crate) fn original_native_restoration_upload_counter_scratch_data() -> usize {
    size_of::<NativeRestorationUploadAttempt>()
        + size_of::<OriginalRestorationUploadPermit>()
        + size_of::<[Option<Rc<RefCell<NativeRestorationUploadAttempt>>>; 2]>()
        + size_of::<PacketRestorationActivationUploadArtifact>() * 2
        + size_of::<PacketRestorationActivationUploadContext>() * 2
        + size_of::<Result<PacketRestorationActivationUploadArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationUploadContext, ProviderError>>()
        + size_of::<Result<OriginalRestorationUploadPermit, ProviderError>>()
        + size_of::<
            Result<std::cell::Ref<'static, NativeRestorationUploadAttempt>, std::cell::BorrowError>,
        >()
        + size_of::<
            Result<
                std::cell::RefMut<'static, NativeRestorationUploadAttempt>,
                std::cell::BorrowMutError,
            >,
        >()
        + size_of::<
            Result<
                std::cell::Ref<'static, Envelope>,
                std::cell::Ref<'static, NativeRestorationUploadAttempt>,
            >,
        >()
        + size_of::<std::slice::Iter<'static, Id>>()
        + size_of::<
            std::iter::Enumerate<
                std::slice::Iter<'static, Option<Rc<RefCell<NativeRestorationUploadAttempt>>>>,
            >,
        >()
        + size_of::<[(usize, &'static NativeRestorationUploadAttempt); 2]>()
        + size_of::<std::array::IntoIter<(usize, &'static NativeRestorationUploadAttempt), 2>>()
        + size_of::<Option<(usize, bool)>>()
        + size_of::<crate::bodies::BlobBeginRequest>()
        + size_of::<crate::bodies::BlobChunkRequest>()
        + size_of::<crate::bodies::BlobFinishRequest>()
        + size_of::<Result<crate::bodies::RequestBody, ProviderError>>()
        + size_of::<Result<crate::bodies::ResponseBody, ProviderError>>()
        + size_of::<Vec<u8>>()
        + size_of::<serde_json::Value>() * 2
        + size_of::<serde_json::Map<String, serde_json::Value>>() * 2
        + size_of::<crate::bodies::ResponseShape>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<(crate::bodies::RequestBody, crate::bodies::RequestBody)>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<crate::reference_packet::control::PacketControlReply, ProviderError>>()
        + size_of::<crate::bodies::BlobBeginResult>()
        + size_of::<crate::bodies::BlobChunkResult>()
        + size_of::<crate::bodies::BlobFinishResult>()
        + size_of::<[usize; 8]>()
}

impl NativeAckBoot {
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn observe_restoration_upload_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        for slot in &self.restoration_uploads {
            if let Some(attempt) = slot {
                observer.shared_original(
                    crate::retained_metadata::aliases::MetadataSharedKind::NativeRestorationUploadAttempt,
                    attempt.as_ref(),
                )?;
                let flight = attempt.try_borrow().map_err(|_| borrowed())?;
                flight.ensure_origin()?;
                flight.observe_settled_history_metadata_data(observer)?;
            }
        }
        Ok(())
    }
}

fn completed_upload_result(
    result: impl serde::Serialize,
) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
    fn object(
        value: impl serde::Serialize,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ProviderError> {
        match serde_json::to_value(value).map_err(ContractError::from)? {
            serde_json::Value::Object(object) => Ok(object),
            _ => Err(refused()),
        }
    }
    object(crate::bodies::ResponseShape::Completed {
        operation_state: crate::bodies::OperationState::Completed,
        result: object(result)?,
        extensions: crucible_node_format::Extensions::new(),
    })
}

// The caller has authenticated transfer, signed row and exact chunk width. This
// final raw-bank cut independently prevents an offset or allocation extension.
pub(super) fn append_upload_chunk_data(
    bank: &mut Vec<u8>,
    offset: U64,
    bytes: &[u8],
) -> Result<usize, ProviderError> {
    let offset = usize::try_from(offset.get()).map_err(|_| refused())?;
    if offset != bank.len() || bytes.is_empty() {
        return Err(refused());
    }
    let next = offset.checked_add(bytes.len()).ok_or_else(refused)?;
    if next > bank.capacity() {
        return Err(refused());
    }
    bank.extend_from_slice(bytes);
    Ok(next)
}

#[path = "upload/settled.rs"]
mod settled;
