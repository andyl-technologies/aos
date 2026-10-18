//! Signs two independently admitted content uploads before World assignment.
//!
//! The genuine owned World claim and one armed SourceRead cover both original
//! upload cuts and the later activation assignment. Source signs each actual
//! BlobBegin, retains its proof and normalized originals before sending, and
//! refuses any retry or final World assignment before both uploads finish.

use super::*;
use crucible_node_contract::U64;
use crucible_node_provider::bodies::{MethodResult, OperationState, ResponseShape};

/// Sends the two genuine content originals beneath the same owned phase.
///
/// # Errors
/// Refuses changed scope/content/quotas, replay, failed currentness, upload
/// protocol refusal or a foreign terminal. Failed Source and SDK partials remain.
pub(super) fn publish_world_uploads(
    controller: &mut CnpController,
    emitter: &OriginalCanonicalBlobAckEmitter,
    key: &[u8; 32],
    attempt: &mut OriginalSourceRestorationActivationAttempt,
    scope: &PacketRestorationActivationScope,
    admitted: &OriginalSourceRestorationActivationConstructionData,
    provider: &OriginalInstalledRestorationActivationConstructionData,
    mut before_effect: impl FnMut() -> Result<(), RuntimeError>,
) -> Result<(), RuntimeError> {
    for role in [
        PacketRestorationActivationUploadRole::Coordinator,
        PacketRestorationActivationUploadRole::Manifest,
    ] {
        attempt.begin_upload(role)?;
        let bodies = attempt.world_bodies()?;
        let content = match role {
            PacketRestorationActivationUploadRole::Coordinator => &bodies.coordinator,
            PacketRestorationActivationUploadRole::Manifest => &bodies.manifest,
        };
        let chunk = provider.upload_chunk_bytes_data(role);
        if chunk == 0
            || content.bytes.len() > provider.upload_maximum_content_bytes_data(role)
            || provider.upload_maximum_frame_bytes_data(role) != admitted.maximum_frame_bytes_data()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let requests = content
            .bytes
            .len()
            .div_ceil(chunk)
            .checked_add(2)
            .ok_or(RuntimeError::ResourceLimit)?;
        let request = PacketRestorationActivationUploadRequest {
            schema: PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE.into(),
            scope: scope.clone(),
            role,
            coordinator: bodies.coordinator.reference.clone(),
            manifest: bodies.manifest.reference.clone(),
            chunk_bytes: U64::new(u64::try_from(chunk).map_err(|_| RuntimeError::ResourceLimit)?),
            maximum_frame_bytes: U64::new(
                u64::try_from(admitted.maximum_frame_bytes_data())
                    .map_err(|_| RuntimeError::ResourceLimit)?,
            ),
            maximum_requests: U64::new(
                u64::try_from(requests).map_err(|_| RuntimeError::ResourceLimit)?,
            ),
            native_allocation: provider.upload_native_allocation_data(role),
        };
        request
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        attempt.retain_upload_value(
            role,
            0,
            serde_json::to_value(&request).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
        )?;
        let mut marker = controller
            .prepare_original_installed_restoration_upload(emitter, request, provider)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let assigned = restoration_activation_upload_assigned_request_digest(
            marker
                .original()
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            role,
            admitted.maximum_frame_bytes_data(),
        )
        .map_err(|_| RuntimeError::InvalidReceipt)?;
        let context = PacketRestorationActivationUploadContext {
            request: serde::Deserialize::deserialize(attempt.upload_value(role, 0)?)
                .map_err(|_| RuntimeError::InvalidReceipt)?,
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        let proof = restoration_activation_upload_proof_data(key, &context)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let artifact = PacketRestorationActivationUploadArtifact {
            request: context.request,
            proof,
        };
        attempt.retain_upload_value(
            role,
            1,
            serde_json::to_value(&artifact).map_err(|_| RuntimeError::InvalidReceipt)?,
            MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
        )?;
        marker
            .seal(emitter, artifact)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        attempt.retain_upload_value(
            role,
            2,
            serde_json::to_value(
                marker
                    .original()
                    .map_err(|_| RuntimeError::InvalidReceipt)?,
            )
            .map_err(|_| RuntimeError::InvalidReceipt)?,
            admitted.maximum_frame_bytes_data(),
        )?;

        before_effect()?;
        marker
            .publish_begin_into(emitter)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        before_effect()?;
        let bodies = attempt.world_bodies()?;
        let bytes = match role {
            PacketRestorationActivationUploadRole::Coordinator => &bodies.coordinator.bytes,
            PacketRestorationActivationUploadRole::Manifest => &bodies.manifest.bytes,
        };
        marker
            .publish_remaining_into(emitter, bytes)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        drop(marker);
        before_effect()?;
        let completed = controller
            .original_completed_installed_restoration_upload_data(emitter, role)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        authenticate_completed_upload(attempt, &completed, role, key, admitted)?;
        attempt.retain_upload_value(
            role,
            3,
            serde_json::to_value(completed.response()).map_err(|_| RuntimeError::InvalidReceipt)?,
            admitted.maximum_frame_bytes_data(),
        )?;
        attempt.finish_upload(role)?;
    }
    Ok(())
}

fn authenticate_completed_upload(
    attempt: &OriginalSourceRestorationActivationAttempt,
    completed: &crucible_node_provider::client::CompletedOriginalInstalledRestorationUpload<'_>,
    role: PacketRestorationActivationUploadRole,
    key: &[u8; 32],
    admitted: &OriginalSourceRestorationActivationConstructionData,
) -> Result<(), RuntimeError> {
    let artifact: PacketRestorationActivationUploadArtifact =
        serde::Deserialize::deserialize(attempt.upload_value(role, 1)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    if completed.request_data() != &artifact.request
        || artifact.request.role != role
        || !completed.response().extensions.is_empty()
        || completed.response().body.keys().any(|key| {
            !matches!(
                key.as_str(),
                "status" | "operation_state" | "result" | "extensions"
            )
        })
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let assigned = restoration_activation_upload_assigned_request_digest(
        completed.original(),
        role,
        admitted.maximum_frame_bytes_data(),
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    let context = PacketRestorationActivationUploadContext {
        request: artifact.request,
        assigned_request: Bytes::new(assigned.to_vec()),
    };
    verify_restoration_activation_upload_proof_data(key, &context, &artifact.proof)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let expected =
        serde_json::to_value(completed.original()).map_err(|_| RuntimeError::InvalidReceipt)?;
    if &expected != attempt.upload_value(role, 2)? {
        return Err(RuntimeError::ForeignAuthority);
    }
    let expected_transfer = completed
        .original()
        .body
        .get("transfer_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(RuntimeError::InvalidReceipt)?;
    authenticate_upload_terminal_data(
        completed.response(),
        completed
            .response_body_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?,
        context.request.content_ref_data(),
        expected_transfer,
    )?;
    Ok(())
}

fn authenticate_upload_terminal_data(
    terminal: &crucible_node_provider::envelope::Envelope,
    body: &ResponseBody,
    expected_content: &ContentRef,
    expected_transfer: &str,
) -> Result<(), RuntimeError> {
    if terminal.protocol != "CNP/1"
        || terminal.message != crucible_node_provider::envelope::MessageKind::Response
        || terminal.method != crucible_node_provider::envelope::Method::BlobFinish
        || !terminal.extensions.is_empty()
        || terminal.body.keys().any(|key| {
            !matches!(
                key.as_str(),
                "status" | "operation_state" | "result" | "extensions"
            )
        })
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result,
        extensions,
    } = &body.shape
    else {
        return Err(RuntimeError::InvalidReceipt);
    };
    let Some(MethodResult::BlobFinish(finished)) = &body.result else {
        return Err(RuntimeError::InvalidReceipt);
    };
    if !extensions.is_empty()
        || &finished.content != expected_content
        || finished.transfer_id.as_str() != expected_transfer
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let actual_result = serde_json::to_value(finished).map_err(|_| RuntimeError::InvalidReceipt)?;
    if actual_result.as_object() != Some(result) {
        return Err(RuntimeError::ForeignAuthority);
    }
    Ok(())
}

// This is a sticky production DATA ledger beneath the genuine Core claim. It
// cannot manufacture a Source, native permit or completed upload response.
pub(super) struct UploadOrder {
    next: usize,
    in_flight: bool,
    failed: bool,
}

impl UploadOrder {
    pub(super) fn new() -> Self {
        Self {
            next: 0,
            in_flight: false,
            failed: false,
        }
    }

    pub(super) fn begin(
        &mut self,
        role: PacketRestorationActivationUploadRole,
    ) -> Result<(), RuntimeError> {
        if self.failed || self.in_flight || self.next != role.ordinal_data() {
            self.failed = true;
            return Err(RuntimeError::OutstandingObligations);
        }
        self.in_flight = true;
        Ok(())
    }

    pub(super) fn authenticate_in_flight(
        &self,
        role: PacketRestorationActivationUploadRole,
    ) -> Result<(), RuntimeError> {
        if self.failed || !self.in_flight || self.next != role.ordinal_data() {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        role: PacketRestorationActivationUploadRole,
    ) -> Result<(), RuntimeError> {
        if self.authenticate_in_flight(role).is_err() {
            self.failed = true;
            return Err(RuntimeError::OutstandingObligations);
        }
        self.next = self
            .next
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.in_flight = false;
        Ok(())
    }

    pub(super) fn authenticate_complete(&self) -> Result<(), RuntimeError> {
        if self.failed || self.in_flight || self.next != 2 {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_upload_ledger_refuses_skipped_repeated_partial_and_post_failure_completion() {
        use PacketRestorationActivationUploadRole::{Coordinator, Manifest};
        let mut complete = UploadOrder::new();
        assert!(complete.authenticate_complete().is_err());
        complete.begin(Coordinator).unwrap();
        assert!(complete.authenticate_complete().is_err());
        complete.finish(Coordinator).unwrap();
        assert!(complete.authenticate_complete().is_err());
        complete.begin(Manifest).unwrap();
        complete.finish(Manifest).unwrap();
        complete.authenticate_complete().unwrap();
        assert!(complete.begin(Manifest).is_err());
        assert!(complete.authenticate_complete().is_err());

        let mut skipped = UploadOrder::new();
        assert!(skipped.begin(Manifest).is_err());
        assert!(skipped.begin(Coordinator).is_err());
        let mut partial = UploadOrder::new();
        partial.begin(Coordinator).unwrap();
        assert!(partial.begin(Coordinator).is_err());
        assert!(partial.finish(Coordinator).is_err());
        assert!(partial.begin(Manifest).is_err());
    }
}

pub(super) fn counter_scratch_data() -> usize {
    size_of::<UploadOrder>()
        + size_of::<(
            &serde_json::Map<String, serde_json::Value>,
            &crucible_node_contract::Extensions,
            &crucible_node_provider::bodies::BlobFinishResult,
        )>()
        + size_of::<Option<&MethodResult>>()
        + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
        + size_of::<serde_json::map::Keys<'static>>()
        + size_of::<(
            &crucible_node_provider::envelope::Envelope,
            &ResponseBody,
            &ContentRef,
            &str,
        )>()
        + size_of::<serde_json::Value>()
        + size_of::<[PacketRestorationActivationUploadRole; 2]>()
        + size_of::<std::array::IntoIter<PacketRestorationActivationUploadRole, 2>>()
        + size_of::<PacketRestorationActivationUploadRequest>()
        + size_of::<PacketRestorationActivationUploadContext>()
        + size_of::<PacketRestorationActivationUploadArtifact>()
        + size_of::<Result<PacketRestorationActivationUploadRequest, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationUploadArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationProof, crucible_node_provider::ProviderError>>(
        )
        + size_of::<
            crucible_node_provider::client::PreparedOriginalInstalledRestorationUpload<'static>,
        >()
        + size_of::<
            Result<
                crucible_node_provider::client::PreparedOriginalInstalledRestorationUpload<'static>,
                crucible_node_provider::ProviderError,
            >,
        >()
        + size_of::<
            crucible_node_provider::client::CompletedOriginalInstalledRestorationUpload<'static>,
        >()
        + size_of::<
            Result<
                crucible_node_provider::client::CompletedOriginalInstalledRestorationUpload<
                    'static,
                >,
                crucible_node_provider::ProviderError,
            >,
        >()
        + size_of::<Result<&ResponseBody, crucible_node_provider::ProviderError>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<&str, RuntimeError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Option<usize>>()
        + size_of::<&PacketCompleteSemanticSource>()
        + size_of::<&OriginalInstalledRestorationActivationClaim>()
        + size_of::<&mut CnpController>()
        + size_of::<&OriginalCanonicalBlobAckEmitter>()
        + size_of::<&[u8; 32]>()
        + size_of::<&mut OriginalSourceRestorationActivationAttempt>()
        + size_of::<&PacketRestorationActivationScope>()
        + size_of::<&OriginalSourceRestorationActivationConstructionData>()
        + size_of::<&OriginalInstalledRestorationActivationConstructionData>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Result<(), crucible_node_provider::ProviderError>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<Result<[u8; 32], crucible_node_provider::ProviderError>>()
}

#[cfg(test)]
mod terminal_tests {
    use super::*;
    use crucible_node_provider::bodies::{BlobFinishResult, EffectCertainty, ErrorRecord};
    use crucible_node_provider::envelope::{Envelope, MessageKind, Method, Nullable};

    fn completed(result: BlobFinishResult) -> ResponseBody {
        ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: serde_json::to_value(&result)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone(),
                extensions: Default::default(),
            },
            result: Some(MethodResult::BlobFinish(result)),
        }
    }

    fn terminal(body: &ResponseBody) -> Envelope {
        // This is an inert closed DTO, not a Controller completion or permit.
        Envelope {
            protocol: "CNP/1".into(),
            message: MessageKind::Response,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(None),
            operation_id: Nullable(None),
            sequence: U64::new(1),
            method: Method::BlobFinish,
            body: serde_json::to_value(&body.shape)
                .unwrap()
                .as_object()
                .unwrap()
                .clone(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn actual_upload_terminal_entry_refuses_foreign_content_transfer_extensions_and_error() {
        let content =
            canonical::content_ref(b"actual complete world body", "application/json").unwrap();
        let foreign =
            canonical::content_ref(b"different complete body", "application/json").unwrap();
        let transfer = Id::new("actual-upload-transfer").unwrap();
        let result = BlobFinishResult {
            transfer_id: transfer.clone(),
            content: content.clone(),
        };
        let body = completed(result.clone());
        let envelope = terminal(&body);
        authenticate_upload_terminal_data(&envelope, &body, &content, transfer.as_str()).unwrap();
        assert!(
            authenticate_upload_terminal_data(&envelope, &body, &foreign, transfer.as_str())
                .is_err()
        );
        assert!(
            authenticate_upload_terminal_data(&envelope, &body, &content, "foreign-transfer")
                .is_err()
        );

        let mut wrong_method = terminal(&body);
        wrong_method.method = Method::WorldActivate;
        assert!(
            authenticate_upload_terminal_data(&wrong_method, &body, &content, transfer.as_str())
                .is_err()
        );
        let mut extra = terminal(&body);
        extra
            .extensions
            .insert("unselected".into(), serde_json::Value::Bool(true));
        assert!(
            authenticate_upload_terminal_data(&extra, &body, &content, transfer.as_str()).is_err()
        );
        let mut extra = terminal(&body);
        extra
            .body
            .insert("unselected".into(), serde_json::Value::Bool(true));
        assert!(
            authenticate_upload_terminal_data(&extra, &body, &content, transfer.as_str()).is_err()
        );
        let mut extra = completed(result);
        let ResponseShape::Completed { result, .. } = &mut extra.shape else {
            panic!("completed fixture changed")
        };
        result.insert("unselected".into(), serde_json::Value::Bool(true));
        assert!(
            authenticate_upload_terminal_data(
                &terminal(&extra),
                &extra,
                &content,
                transfer.as_str()
            )
            .is_err()
        );

        let error = ResponseBody {
            shape: ResponseShape::Error {
                operation_state: OperationState::NotStarted,
                error: ErrorRecord {
                    code: "RESOURCE_EXHAUSTED".into(),
                    message: "inert DATA refusal".into(),
                    effect: EffectCertainty::NotStarted,
                    retryable: false,
                    details: Default::default(),
                },
                extensions: Default::default(),
            },
            result: None,
        };
        assert!(
            authenticate_upload_terminal_data(
                &terminal(&error),
                &error,
                &content,
                transfer.as_str()
            )
            .is_err()
        );
    }
}

/// Records the actual sticky upload ledger without creating another ordinal.
#[derive(serde::Serialize)]
pub(super) struct SourceActivationUploadOrderHistoryData {
    next: usize,
    in_flight: bool,
    failed: bool,
}

impl UploadOrder {
    pub(super) fn historical_data(&self) -> SourceActivationUploadOrderHistoryData {
        let Self {
            next,
            in_flight,
            failed,
        } = self;
        SourceActivationUploadOrderHistoryData {
            next: *next,
            in_flight: *in_flight,
            failed: *failed,
        }
    }

    pub(super) fn historical_counter_scratch_data() -> usize {
        size_of::<SourceActivationUploadOrderHistoryData>() + size_of::<&Self>()
    }
}

impl UploadOrder {
    pub(super) fn settled17_once_data(&self) -> (usize, bool, bool) {
        (self.next, self.in_flight, self.failed)
    }
}
