//! Counts actual typed inputs and every initialized Native18 partial owner.

use super::*;
use crate::retained_metadata::{ObserveMetadata, aliases::MetadataSharedKind};

macro_rules! fields {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl ObserveMetadata for $ty {
            fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
                let Self { $($field),+ } = self;
                $(observer.observe($field)?;)+
                Ok(())
            }
        }
    };
}

// Exact original typed DATA observers; no old SDK owner is selected.
fields!(
    crate::reference_packet::service::complete_restore::PacketCompleteRestoreRequest,
    schema,
    archive_index,
    capture_manifest,
    owner_state,
    journal,
    source_runtime,
    backend_implementation,
    backend_schema,
    archived_cut,
    archived_ordinal,
    target_world,
    target_owner,
    target_owner_binding,
    target_activation,
    target_generation,
    target_owner_generation,
    mapping,
    nonce
);
fields!(
    PacketCompleteRestoreInputAllocation,
    maximum_known_requested_bytes,
    maximum_input_bytes,
    maximum_nodes,
    maximum_depth,
    maximum_owned_backing_bytes,
    maximum_tree_entries,
    maximum_metadata_rows,
    maximum_literal_backing_bytes,
    maximum_content_transfers,
    maximum_content_objects,
    maximum_content_groups,
    maximum_content_bytes,
    maximum_content_metadata_bytes,
    maximum_model_bytes
);
fields!(
    PacketCompleteRestorePrepareRequest,
    schema,
    restoration,
    host_protocol,
    native_protocol,
    native_control,
    native_anchor,
    transaction_id,
    generation,
    allocation
);
fields!(
    PacketCompleteRestoreCommitRequest,
    schema,
    prepare,
    capture_terminal,
    prepare_request_id,
    prepare_request_sequence,
    prepare_request_digest,
    prepare_response_sequence,
    prepare_response_digest,
    transfer_token
);
fields!(
    PacketNativeImport17Limits,
    role_maximums,
    immutable_objects,
    immutable_bytes,
    immutable_depth,
    maximum_nodes,
    maximum_requested_bytes,
    maximum_target_requested_bytes,
    maximum_before_bytes
);
fields!(
    PacketNativeImport17Proof,
    schema,
    algorithm,
    context_digest,
    mac
);
fields!(
    PacketNativeImport17PrepareReceipt,
    schema,
    algorithm,
    import_binding_digest,
    context_digest,
    prepare_digest,
    input_roster,
    transfer_token,
    generation,
    native_sequence,
    assigned_response,
    mac
);

fields!(
    PacketNativeImport18Binding,
    schema,
    prepare_digest,
    native_family,
    native_before,
    controller17,
    source_family,
    source17,
    node25,
    geometry_identity,
    role_extents,
    limits,
    normalization,
    normalization_maximum,
    semantic_spend_family,
    semantic_spend,
    semantic_spend_maximum
);

// Required family labels are inline DATA, not opaque owner aliases.
impl ObserveMetadata for PacketNativeImport18SourceFamily {
    fn observe_metadata(&self, _observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Captured17 | Self::Captured18 | Self::Imported18 => Ok(()),
        }
    }
}

impl ObserveMetadata for PacketNativeImport18NativeFamily {
    fn observe_metadata(&self, _observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Snapshot17 | Self::Snapshot18 => Ok(()),
        }
    }
}

impl ObserveMetadata for PacketNativeImport18SemanticSpendFamily {
    fn observe_metadata(&self, _observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::Legacy17 | Self::Complete18 => Ok(()),
        }
    }
}

// Exact borrowed captures of the defining synchronous phase metadata scope.
type PhaseMetadataLoans<'a> = (
    &'a Option<Id>,
    &'a Option<BeginRequest>,
    &'a PacketCompleteRestorePrepareRequest,
    &'a Option<Value>,
    &'a Option<Value>,
    &'a Option<Value>,
    &'a Option<PacketNativeImport17Proof>,
    &'a Option<Value>,
    &'a Option<Envelope>,
    &'a Vec<u8>,
    &'a Option<crate::transport::RetainedFrame>,
    &'a Option<Envelope>,
    &'a Option<crate::connection::ReceivedFrame>,
    &'a Option<ResponseBody>,
    &'a Option<PacketNativeImport17PrepareReceipt>,
);

pub(super) fn profile_scope_counter_scratch_data() -> usize {
    std::mem::size_of::<PhaseMetadataLoans<'static>>()
        + std::mem::size_of::<&mut MetadataObserver<'static>>()
        + std::mem::size_of::<bool>()
        + std::mem::size_of::<Result<(), ProviderError>>()
}

impl<T: ObserveMetadata> AssignedPhase<T> {
    fn observe(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            stage: _,
            request_id,
            baseline,
            request,
            body,
            payload,
            binding_value,
            proof,
            proof_value,
            original,
            bytes,
            literal_slot: _,
            cut: _,
            json_profile,
            raw,
            response,
            received,
            decoded,
            prepare_receipt,
        } = self;
        let observe_fields = |observer: &mut MetadataObserver<'_>| {
            observer.observe(request_id)?;
            observer.observe(baseline)?;
            observer.observe(request)?;
            observer.observe(body)?;
            observer.observe(payload)?;
            observer.observe(binding_value)?;
            observer.observe(proof)?;
            observer.observe(proof_value)?;
            observer.observe(original)?;
            observer.vector::<u8>(bytes.capacity())?;
            if let Some(crate::transport::RetainedFrame { value, bytes }) = raw {
                observer.observe(value)?;
                observer.vector::<u8>(bytes.capacity())?;
            }
            observer.observe(response)?;
            if let Some(frame) = received {
                frame.observe_native_import17_upload_data(observer)?;
            }
            if let Some(decoded) = decoded {
                decoded.observe_native_import18_metadata_data(observer)?;
            }
            observer.observe(prepare_receipt)
        };
        if json_profile.has_constructed_population_data() {
            observer.with_native_import18_json_profile_data(*json_profile, observe_fields)
        } else {
            // A row mismatch fails before any new bank construction. The actual
            // preexisting typed inputs retain their ordinary observer contract.
            observe_fields(observer)
        }
    }
}

impl OriginalNativeImport18Assignment {
    /// Counts actual initialized backing, including failed and spare phase banks.
    ///
    /// Source separately counts this inline header and the Controller's cache,
    /// literal/guard owners. No successful-stage or equal-content discount applies.
    ///
    /// The caller first admits retained_metadata_counter_scratch_data's actual
    /// result; a baseline64 counter cannot cover expanded failed Values.
    ///
    /// # Errors
    /// Refuses a foreign original actor, overflow or metadata traversal exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        self.observe_actual_history_data(&mut observer)?;
        Ok(observer.finish())
    }

    /// Quotes actual metadata recursion from retained constructor profiles.
    ///
    /// This reads only real profile scalars and frame-spine headers. The caller
    /// admits static history/assignment controls first, then this returned S
    /// before retained_metadata_data or a history serialization prewalk. It
    /// performs no Value traversal, allocation, serialization or phase grant.
    ///
    /// # Errors
    /// Refuses a foreign creator or checked geometry overflow.
    pub fn retained_metadata_counter_scratch_data(&self) -> Result<usize, ProviderError> {
        self.controller.ensure_current()?;
        let depth = self
            .prepare
            .json_profile
            .maximum_depth_data()
            .max(self.uploads.metadata_maximum_depth_data());
        let frames = depth
            .checked_mul(
                MetadataObserver::native_import18_json_metadata_frame_counter_scratch_data(),
            )
            .ok_or_else(credit)?;
        CnpController::original_native_import18_assignment_counter_scratch_data()
            .checked_add(frames)
            .ok_or_else(credit)
    }

    pub(super) fn observe_actual_history_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        let Self {
            controller,
            binding,
            expected_backend_schema,
            normalization,
            prepare,
            uploads,
        } = self;

        observer.shared_original(MetadataSharedKind::ProtocolOwner, controller.as_ref())?;
        observer.observe(binding)?;
        observer.observe(expected_backend_schema)?;
        observer.vector::<u8>(normalization.capacity())?;

        prepare.observe(observer)?;
        uploads.observe(observer)?;
        Ok(())
    }
}

pub(super) fn facts<T: ObserveMetadata>(
    value: &T,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(value)?;
    Ok(observer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bodies::BeginKind;

    #[test]
    fn census_keeps_failed_phase_spare_banks_without_qualifying_completion() {
        let baseline = BeginRequest {
            kind: BeginKind::PrepareRestore,
            binding_hash: canonical::hash("cnp.owner-binding.v1", b"inert census data").unwrap(),
            owner_generation: U64::new(1),
            activation_id: Nullable(None),
            world_generation: U64::new(1),
            arguments: Default::default(),
            extensions: Default::default(),
        };
        let mut partial = AssignedPhase::new(
            Id::new("data/partial-phase").unwrap(),
            baseline,
            String::new(),
        );
        partial.stage = Stage::Sealing;
        partial.bytes = Vec::with_capacity(137);
        let byte_capacity = partial.bytes.capacity();
        let mut text = String::with_capacity(213);
        text.push_str("initialized failed proof projection");
        let text_capacity = text.capacity();
        partial.proof_value = Some(Value::String(text));

        let mut observer = MetadataObserver::new();
        partial.observe(&mut observer).unwrap();
        let actual = observer.finish();

        assert!(actual.vector_capacity_bytes >= byte_capacity);
        assert!(actual.string_capacity_bytes >= text_capacity);
        assert!(partial.stage == Stage::Sealing);
        assert!(partial.response.is_none());
    }
}

impl OriginalNativeImport18Assignment {
    /// Observes the actual Source-retained typed partial inputs without copying.
    ///
    /// Each present field uses the same exhaustive defining observer as the SDK
    /// assignment. Absent inputs contribute no invented future allocation. This
    /// DATA observation checks no currentness, admission or native permission.
    /// The caller separately admits source_input_metadata_counter_scratch_data
    /// and keeps its genuine Source phase/origin guards around the observation.
    ///
    /// # Errors
    /// Refuses actual metadata overflow, unsupported JSON depth or observer work
    /// exhaustion; every borrowed partial remains unchanged on either outcome.
    pub fn source_input_retained_metadata_data(
        request_id: Option<&Id>,
        baseline: Option<&BeginRequest>,
        prepare: Option<&PacketCompleteRestorePrepareRequest>,
        commit: Option<&PacketCompleteRestoreCommitRequest>,
        binding: Option<&PacketNativeImport18Binding>,
    ) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        let mut observer = MetadataObserver::new();
        Self::observe_source_inputs_data(
            request_id,
            baseline,
            prepare,
            commit,
            binding,
            &mut observer,
        )?;
        Ok(observer.finish())
    }

    pub(super) fn observe_source_inputs_data(
        request_id: Option<&Id>,
        baseline: Option<&BeginRequest>,
        prepare: Option<&PacketCompleteRestorePrepareRequest>,
        commit: Option<&PacketCompleteRestoreCommitRequest>,
        binding: Option<&PacketNativeImport18Binding>,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(id) = request_id {
            observer.observe(id)?;
        }
        if let Some(baseline) = baseline {
            observer.observe(baseline)?;
        }
        if let Some(prepare) = prepare {
            observer.observe(prepare)?;
        }
        if let Some(commit) = commit {
            observer.observe(commit)?;
        }
        if let Some(binding) = binding {
            observer.observe(binding)?;
        }
        Ok(())
    }

    /// Names the actual typed visitor and borrowed optional input controls.
    ///
    /// The conservative defining assignment visitor declaration is reused for
    /// the exact same private field observers; it runs no actor or phase guard.
    pub fn source_input_metadata_counter_scratch_data() -> usize {
        use std::mem::size_of;
        type Inputs<'a> = (
            Option<&'a Id>,
            Option<&'a BeginRequest>,
            Option<&'a PacketCompleteRestorePrepareRequest>,
            Option<&'a PacketCompleteRestoreCommitRequest>,
            Option<&'a PacketNativeImport18Binding>,
        );

        CnpController::original_native_import18_assignment_counter_scratch_data()
            + size_of::<Inputs<'static>>()
            + size_of::<MetadataObserver<'static>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
    }
}

#[cfg(test)]
mod source_input_tests {
    use super::*;

    #[test]
    fn actual_source_id_backing_is_counted_and_none_allocates_nothing() {
        let empty = OriginalNativeImport18Assignment::source_input_retained_metadata_data(
            None, None, None, None, None,
        )
        .unwrap();
        let id = Id::new("source-partial/retained-id").unwrap();

        let facts = OriginalNativeImport18Assignment::source_input_retained_metadata_data(
            Some(&id),
            None,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(empty.string_capacity_bytes, 0);
        assert_eq!(empty.vector_capacity_bytes, 0);
        assert_eq!(empty.shared_value_bytes, 0);
        assert_eq!(facts.string_capacity_bytes, id.allocated_capacity());
        assert_eq!(facts.string_banks, empty.string_banks + 1);
    }
}

impl OriginalNativeImport18Assignment {
    /// Quotes ordinary Bytes formatting from the same actual Source partials.
    ///
    /// This grant-free observer allocates nothing and runs no serializer. The
    /// caller first admits history_counter_scratch_data; retained storage and
    /// whole output encoding remain its independently priced owners.
    ///
    /// # Errors
    /// Refuses actual field traversal or base64 extent overflow.
    pub fn source_input_history_formatter_data(
        request_id: Option<&Id>,
        baseline: Option<&BeginRequest>,
        prepare: Option<&PacketCompleteRestorePrepareRequest>,
        commit: Option<&PacketCompleteRestoreCommitRequest>,
        binding: Option<&PacketNativeImport18Binding>,
    ) -> Result<usize, ProviderError> {
        let mut observer = MetadataObserver::new();
        if let Some(id) = request_id {
            observer.observe(id)?;
        }
        if let Some(baseline) = baseline {
            observer.observe(baseline)?;
        }
        if let Some(prepare) = prepare {
            observer.observe(prepare)?;
        }
        if let Some(commit) = commit {
            observer.observe(commit)?;
        }
        if let Some(binding) = binding {
            observer.observe(binding)?;
        }
        observer
            .ordinary_bytes_formatter_data()
            .maximum_temporary_requested_bytes_data()
    }
}
