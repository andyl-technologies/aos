//! Observes retained Capture results and original Source protocol associations.
//!
//! Raw response maps and their decoded typed results own independent backing.
//! Both are counted. These facts omit the caller's outer inline slots and do
//! not validate a receipt, authenticate native effects or grant source rights.

use super::*;
use crate::bodies::*;
use crate::reference_packet::service::confirmation::{
    PacketNativeAfterConfirmationReceipt, PacketNativeAfterConfirmationRequest,
};

/// Borrows the closed protocol families retained by complete Source custody.
pub enum RetainedCaptureProtocolData<'a> {
    /// Borrows a Capture registration, Capture terminal or Poll response.
    ///
    /// Refusals are also covered; other typed method-result families refuse.
    Response(&'a ResponseBody),
    /// Borrows the actual independently decoded after-confirmation receipt.
    AfterConfirmation(&'a PacketNativeAfterConfirmationReceipt),
    /// Borrows every actual bank and association in a snapshot reservation.
    SnapshotReservation(&'a crate::protocol_snapshot::ProtocolSnapshotReservation),
    /// Borrows the actual original encoded snapshot and its independent banks.
    Snapshot(&'a crate::protocol_snapshot::OriginalProtocolSnapshot),
    /// Borrows post-move custody; the moved encoded Vec remains a separate owner.
    PayloadOwner(&'a crate::protocol_snapshot::OriginalProtocolPayloadOwner),
    /// Borrows the original canonical Blob acknowledgement emitter association.
    AckEmitter(&'a crate::client::OriginalCanonicalBlobAckEmitter),
    /// Borrows the original canonical restoration input uploader association.
    RestoreInputEmitter(&'a crate::client::OriginalCanonicalRestoreInputEmitter),
    /// Borrows ordinary or native Hello custody, including failed partial frames.
    ///
    /// An ordinary journal has no creator field. Its owning Source must check
    /// process/thread origin before lending physical record rows.
    HelloJournal(&'a crate::client::OriginalHelloJournal),
    /// Borrows every retained archived mapping owner, including revoked custody.
    ArchivedMapping(&'a crate::protocol_snapshot::PreparedArchivedProtocolMapping),
    /// Borrows independent restored receipt and underlying model partials.
    ///
    /// Missing or inconsistent partners remain DATA without acquiring native
    /// restoration eligibility. Each real underlying Box retains its own row.
    RestorationNativeEvidence(
        Option<&'a crate::reference_packet::service::complete_restore::PacketNativeRestoredRecord>,
        Option<&'a crate::reference_packet::control::PacketNative5UnderlyingRecord>,
    ),
}

impl RetainedCaptureProtocolData<'_> {
    /// Reports actual retained child capacities and requested-layout facts.
    ///
    /// Equal raw and typed fields receive no alias discount. The owning source
    /// supplies its original-origin guard and separately charges outer inline
    /// slots, metadata traversal scratch and checked tree/header geometry.
    ///
    /// # Errors
    /// Refuses another method family, foreign original creators, borrowed Hello
    /// custody, checked extent overflow or bounded observer exhaustion. It
    /// performs no serialization, lifecycle operation or I/O.
    pub fn observe_retained_metadata(
        &self,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.check_original_creator()?;
        let mut observer = MetadataObserver::new();
        self.observe_into(&mut observer)?;
        Ok(observer.finish())
    }

    /// Appends actual capacity rows without clearing earlier Source components.
    ///
    /// Association creator checks precede the bank loan. The caller separately
    /// authenticates the complete Source and admits simultaneous observation
    /// controls. Partial banks remain DATA and grant no lifecycle authority.
    ///
    /// # Errors
    /// Refuses foreign original creators, busy Hello custody, unsupported result
    /// families, exhausted rows, invalid backing or ordinary traversal limits.
    /// Refusal preserves all previously initialized physical rows.
    pub fn record_retained_metadata_data(
        &self,
        bank: &mut records::PacketRuntimeMetadataRecordBank,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.check_original_creator()?;
        let mut observer = MetadataObserver::appending(bank.recording_bank_data()?);
        self.observe_into(&mut observer)?;
        Ok(observer.finish())
    }

    /// Names concrete borrowed capture, snapshot and observer controls.
    pub fn capacity_counter_scratch_data() -> usize {
        crate::protocol_snapshot::capture_capacity_counter_scratch_data()
            + crate::client::OriginalCanonicalBlobAckEmitter::capacity_counter_scratch_data()
            + crate::client::OriginalCanonicalRestoreInputEmitter::capacity_counter_scratch_data()
            + crate::client::OriginalHelloJournal::capacity_counter_scratch_data()
            + crate::reference_packet::service::complete_restore::activation::restoration_native_capacity_counter_scratch_data()
            + crate::protocol_snapshot::PreparedArchivedProtocolMapping::capacity_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<&mut MetadataObserver<'static>>()
            + size_of::<&mut records::PacketRuntimeMetadataRecordBank>()
            + size_of::<Result<&mut MetadataRecordBank, ProviderError>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }

    /// Checks process/thread custody before a component lends physical rows.
    ///
    /// Portable DTO variants carry no creator of their own. The enclosing Source
    /// supplies its origin check. This predicate tests no registration liveness,
    /// native evidence, lifecycle eligibility or permission to publish.
    ///
    /// # Errors
    /// Refuses an association created by another process or thread.
    pub fn check_original_creator(&self) -> Result<(), ProviderError> {
        match self {
            Self::Response(_)
            | Self::AfterConfirmation(_)
            | Self::RestorationNativeEvidence(_, _) => Ok(()),
            Self::SnapshotReservation(value) => value.check_capacity_creator_data(),
            Self::Snapshot(value) => value.check_capacity_creator_data(),
            Self::PayloadOwner(value) => value.check_capacity_creator_data(),
            Self::AckEmitter(value) => value.check_capacity_creator_data(),
            Self::RestoreInputEmitter(value) => value.check_capacity_creator_data(),
            Self::HelloJournal(value) => value.check_capacity_creator_data(),
            Self::ArchivedMapping(value) => value.check_capacity_creator_data(),
        }
    }

    fn observe_into(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Response(response) => observe_response(response, observer),
            Self::AfterConfirmation(receipt) => observer.observe(*receipt),
            Self::SnapshotReservation(value) => value.observe_capacity_data(observer),
            Self::Snapshot(value) => value.observe_capacity_data(observer),
            Self::PayloadOwner(value) => value.observe_capacity_data(observer),
            Self::AckEmitter(value) => value.observe_capacity_data(observer),
            Self::RestoreInputEmitter(value) => value.observe_capacity_data(observer),
            Self::HelloJournal(value) => value.observe_capacity_data(observer),
            Self::ArchivedMapping(value) => value.observe_capacity_data(observer),
            Self::RestorationNativeEvidence(record, underlying) => {
                crate::reference_packet::service::complete_restore::activation::observe_restoration_native_capacity_data(
                    *record, *underlying, observer,
                )
            }
        }
    }
}

pub(super) fn observe_response(
    response: &ResponseBody,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    let ResponseBody { shape, result } = response;
    observe_response_shape(shape, observer)?;
    match result {
        None => Ok(()),
        Some(MethodResult::BeginAccepted(value)) => observer.observe(value),
        Some(MethodResult::Capture(value)) => observer.observe(value),
        Some(MethodResult::Poll(value)) => observer.observe(value),
        Some(
            MethodResult::Hello(_)
            | MethodResult::Discover(_)
            | MethodResult::Realize(_)
            | MethodResult::Admit(_)
            | MethodResult::Activate(_)
            | MethodResult::Input(_)
            | MethodResult::Observe(_)
            | MethodResult::Cancel(_)
            | MethodResult::QuantumClose(_)
            | MethodResult::WorldActivate(_)
            | MethodResult::Abort(_)
            | MethodResult::Retire(_)
            | MethodResult::BlobBegin(_)
            | MethodResult::BlobChunk(_)
            | MethodResult::BlobFinish(_)
            | MethodResult::Release(_)
            | MethodResult::ExactRun(_)
            | MethodResult::BoundarySettle(_)
            | MethodResult::QuantumBegin(_)
            | MethodResult::Pause(_)
            | MethodResult::PrepareRestore(_)
            | MethodResult::Shutdown(_),
        ) => Err(ProviderError::Correlation(
            "retained Capture result method family differs",
        )),
    }
}

pub(super) fn observe_response_shape(
    shape: &ResponseShape,
    observer: &mut MetadataObserver,
) -> Result<(), ProviderError> {
    match shape {
        ResponseShape::Accepted {
            operation_state,
            result,
            extensions,
        }
        | ResponseShape::Completed {
            operation_state,
            result,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(result)?;
            observer.observe(extensions)?;
        }
        ResponseShape::Error {
            operation_state,
            error,
            extensions,
        } => {
            observer.observe(operation_state)?;
            observer.observe(error)?;
            observer.observe(extensions)?;
        }
    }
    Ok(())
}

fields!(ErrorRecord, code, message, effect, retryable, details);
fields!(BeginAccepted, operation_id, kind);
fields!(
    CaptureArguments,
    capture_id,
    participant_ids,
    cut_id,
    cut,
    event_ordinal,
    ordering_profile,
    preservation_contract
);
fields!(
    CaptureResult,
    capture_manifest,
    owner_state_refs,
    unchanged_cut_receipt
);
fields!(
    PollResult,
    operation_id,
    operation_state,
    outcome,
    observations,
    next_observation_sequence
);
fields!(
    ObservationBatch,
    schema_version,
    execution_owner_id,
    owner_binding_hash,
    world_binding_hash,
    activation_id,
    world_generation,
    owner_generation,
    operation_id,
    grant_id,
    first_sequence,
    last_sequence,
    events,
    visibility,
    measurement_ref,
    extensions
);
fields!(
    PacketNativeAfterConfirmationReceipt,
    schema,
    capture,
    native_after_ref,
    native_after_capacity
);
fields!(
    PacketNativeAfterConfirmationRequest,
    schema,
    capture_request_id,
    capture_request_hash,
    capture_operation_id,
    capture_terminal_hash,
    capture_terminal_sequence,
    native_snapshot_ref,
    native_control_ref,
    native_anchor_ref
);

impl ObserveMetadata for OperationState {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::NotStarted | Self::Running | Self::Completed | Self::Unknown => Ok(()),
        }
    }
}

impl ObserveMetadata for EffectCertainty {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::NotStarted | Self::InProgress | Self::Completed | Self::Unknown => Ok(()),
        }
    }
}

impl ObserveMetadata for Visibility {
    fn observe_metadata(&self, _: &mut MetadataObserver) -> Result<(), ProviderError> {
        match self {
            Self::Staged | Self::Committed => Ok(()),
        }
    }
}

// crucible-lint: allow panic-shortcut -- Retained-capacity controls deliberately panic when their actual spare banks differ.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "checks actual spare-capacity DTO data without native authority"
)]
mod tests {
    use super::*;

    #[test]
    fn capture_arguments_count_spare_roster_and_ordering_profile_backing() {
        let mut participant_ids = Vec::with_capacity(7);
        participant_ids.push(Id::new("data/participant").unwrap());
        let expected_vector_bytes = participant_ids.capacity() * size_of::<Id>();
        let mut ordering_profile = String::with_capacity(113);
        ordering_profile.push_str("superdense-v1");
        let arguments = CaptureArguments {
            capture_id: Id::new("data/capture").unwrap(),
            participant_ids,
            cut_id: Id::new("data/cut").unwrap(),
            cut: Position::new(U64::new(50), U64::new(0), Phase::BoundaryControl),
            event_ordinal: U64::new(0),
            ordering_profile,
            preservation_contract: Id::new("data/preservation").unwrap(),
        };
        let expected_string_bytes = arguments.capture_id.allocated_capacity()
            + arguments.participant_ids[0].allocated_capacity()
            + arguments.cut_id.allocated_capacity()
            + arguments.ordering_profile.capacity()
            + arguments.preservation_contract.allocated_capacity();

        let mut observer = MetadataObserver::new();
        observer.observe(&arguments).unwrap();
        let facts = observer.finish();

        assert_eq!(facts.vector_capacity_bytes, expected_vector_bytes);
        assert_eq!(facts.vector_banks, 1);
        assert_eq!(facts.string_capacity_bytes, expected_string_bytes);
        assert_eq!(facts.string_banks, 5);
        assert_eq!(facts.tree_containers, 0);
    }

    #[test]
    fn capture_response_counts_independent_raw_and_typed_spare_backing() {
        let reference = canonical::content_ref(b"capture data", "application/json").unwrap();
        let mut owners = Vec::with_capacity(4);
        owners.push(reference.clone());
        let vector_bytes = owners.capacity() * size_of::<ContentRef>();
        let mut raw_text = String::with_capacity(97);
        raw_text.push_str("raw result owned separately");
        let raw_capacity = raw_text.capacity();
        let mut raw = serde_json::Map::new();
        raw.insert("data".to_owned(), Value::String(raw_text));
        let response = ResponseBody {
            shape: ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result: raw,
                extensions: Extensions::new(),
            },
            result: Some(MethodResult::Capture(CaptureResult {
                capture_manifest: reference.clone(),
                owner_state_refs: owners,
                unchanged_cut_receipt: reference,
            })),
        };
        let facts = RetainedCaptureProtocolData::Response(&response)
            .observe_retained_metadata()
            .unwrap();
        assert_eq!(facts.vector_capacity_bytes, vector_bytes);
        assert!(facts.string_capacity_bytes >= raw_capacity);
        assert_eq!(facts.vector_banks, 1);
        assert!(facts.tree_containers >= 2);

        let unsupported = ResponseBody {
            shape: response.shape,
            result: Some(MethodResult::BlobChunk(BlobChunkResult {
                transfer_id: Id::new("data/transfer").unwrap(),
                next_offset: U64::new(0),
            })),
        };
        assert!(
            RetainedCaptureProtocolData::Response(&unsupported)
                .observe_retained_metadata()
                .is_err()
        );
    }

    #[test]
    fn capture_poll_counts_empty_observation_capacity_and_owned_error_details() {
        let observations = Vec::with_capacity(3);
        let expected = observations.capacity() * size_of::<ObservationBatch>();
        let response = ResponseBody {
            shape: ResponseShape::Accepted {
                operation_state: OperationState::Running,
                result: Default::default(),
                extensions: Extensions::new(),
            },
            result: Some(MethodResult::Poll(PollResult {
                operation_id: Id::new("data/operation").unwrap(),
                operation_state: OperationState::Running,
                outcome: crate::envelope::Nullable(None),
                observations,
                next_observation_sequence: U64::new(0),
            })),
        };
        let facts = RetainedCaptureProtocolData::Response(&response)
            .observe_retained_metadata()
            .unwrap();
        assert_eq!(facts.vector_capacity_bytes, expected);
        assert_eq!(facts.vector_banks, 1);
        let mut message = String::with_capacity(113);
        message.push_str("retained failure");
        let expected = message.capacity();
        let response = ResponseBody {
            shape: ResponseShape::Error {
                operation_state: OperationState::Unknown,
                error: ErrorRecord {
                    code: "OUTCOME_UNKNOWN".into(),
                    message,
                    effect: EffectCertainty::Unknown,
                    retryable: false,
                    details: serde_json::Map::new(),
                },
                extensions: Extensions::new(),
            },
            result: None,
        };
        let facts = RetainedCaptureProtocolData::Response(&response)
            .observe_retained_metadata()
            .unwrap();
        assert!(facts.string_capacity_bytes >= expected);
    }
}
