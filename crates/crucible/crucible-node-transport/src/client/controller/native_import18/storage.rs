//! Prices actual phase inputs and future original/cache/receive banks as DATA.
//!
//! Only bounded-input Prepare is issued here. Existing Controller, Source input
//! owners, native banks and signing contexts remain independently charged.

use super::*;
use crate::retained_metadata::serialization_storage::{
    actual_serialization_storage_data, original_serialization_counter_scratch_data,
    original_serialization_formatter_temporary_storage_data,
};
use crate::retained_metadata::{
    ObserveMetadata, requested_metadata_backing_storage_data as backing,
};
use serde::ser::SerializeMap;
use std::mem::{align_of, size_of};

/// Binds one actual phase quote to its Controller, frontier and complete inputs.
///
/// Numeric axes are requested-storage DATA, not a Source/native admission. The
/// genuine Source must independently retain and admit the row before assignment.
pub struct OriginalNativeImport18AssignmentStorageData {
    controller: Rc<ProtocolCaptureOwner>,
    frontier: OriginalProtocolStorageFacts,
    phase: PacketNativeImport18Phase,
    identity: blake3::Hash,
    retained: usize,
    transient: usize,
    scratch: usize,
    pub(super) maximum_frame: usize,
    pub(super) json_profile: NativeImport18JsonMetadataProfileData,
}

impl OriginalNativeImport18AssignmentStorageData {
    /// Returns the separately priced new phase/custody backing.
    pub const fn retained_growth_bytes(&self) -> usize {
        self.retained
    }
    /// Returns the separately priced maximum temporary window.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }
    /// Returns fixed defining counters, excluding compiler/recursive stack.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Counts the real retained Controller association of this quote row.
    ///
    /// The enclosing Source separately counts this inline row. No permission
    /// follows from matching this original shared actor.
    ///
    /// # Errors
    /// Refuses a foreign actor, overflow or metadata traversal exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.controller.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(self.controller.as_ref())?;
        Ok(observer.finish())
    }

    pub(super) fn authenticate_prepare_data(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        owner: &OriginalNativeImport18Assignment,
        normalization: &[u8],
    ) -> Result<(), ProviderError> {
        self.authenticate(controller, emitter, PacketNativeImport18Phase::Prepare)?;
        query.authenticate_current(controller, emitter)?;
        let p = &owner.prepare;
        let actual = identity(
            &(
                p.request_id.as_ref().ok_or_else(invalid)?,
                p.baseline.as_ref().ok_or_else(invalid)?,
                &p.request,
                &owner.binding,
                &owner.expected_backend_schema,
                query.original_data().ok_or_else(invalid)?.sequence,
                query.allocation_reference_data().ok_or_else(invalid)?,
            ),
            normalization,
        )?;
        if actual != self.identity {
            return Err(invalid());
        }
        Ok(())
    }

    fn authenticate(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalBlobAckEmitter,
        phase: PacketNativeImport18Phase,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(controller)?;
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &controller.protocol_owner)
            || phase != self.phase
            || self.frontier != controller.original_native5_storage_facts()?
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl CnpController {
    /// Names actual phase, visitor, guard, hash and receive headers before quotation.
    pub fn original_native_import18_assignment_counter_scratch_data() -> usize {
        current_guard_counter_scratch_data()
            + MetadataObserver::native_import18_json_profile_counter_scratch_data()
            + metadata::profile_scope_counter_scratch_data()
            + super::input_upload::retained_counter_scratch_data()
            + size_of::<OriginalNativeImport18Assignment>()
            + size_of::<Option<OriginalNativeImport18Assignment>>()
            + size_of::<OriginalNativeImport18AssignmentStorageData>()
            + size_of::<Result<OriginalNativeImport18AssignmentStorageData, ProviderError>>()
            + prepare_inputs::counter_scratch_data()
            + size_of::<AssignedPhase<PacketCompleteRestorePrepareRequest>>()
            + size_of::<SchemaRef>()
            + size_of::<&SchemaRef>()
            + size_of::<[(PacketNativeImport18InputRole, &ContentRef, U64); 7]>()
            + size_of::<std::slice::Iter<'static, (PacketNativeImport18InputRole, &'static ContentRef, U64)>>()
            + size_of::<PacketNativeImport18Binding>()
            + size_of::<PacketNativeImport17Proof>()
            + size_of::<PacketNativeImport17PrepareReceipt>()
            + size_of::<PacketNativeImport17CommitReceipt>()
            + 4 * size_of::<MetadataObserver<'static>>()
            + 4 * size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<EnvelopeView<'static, PacketCompleteRestorePrepareRequest>>()
            + size_of::<ProofView>()
            + size_of::<HashWriter>()
            + size_of::<blake3::Hash>()
            + size_of::<Option<crate::connection::ReceivedFrame>>()
            + crate::connection::ReceivedFrame::native_import17_upload_counter_scratch_data()
            + crate::connection::ReceivedFrame::borrowed_settled17_counter_scratch_data()
            + size_of::<crate::connection::ReceivedFrame>()
            + size_of::<crate::connection::ReceivedBody>()
            + size_of::<RequestBody>()
            + size_of::<ResponseBody>()
            + size_of::<Result<RequestBody, ProviderError>>()
            + size_of::<Result<ResponseBody, ProviderError>>()
            + size_of::<Option<&Envelope>>()
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<(usize, usize, usize)>()
            + size_of::<[usize; 12]>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + original_serialization_counter_scratch_data()
            + crate::retained_metadata::original_complete_restore_transfer_response_counter_scratch_data()
            + ResponseBody::native_import18_metadata_counter_scratch_data()
            + native_import18_contract_counter_scratch_data()
            + Self::original_selected_restore_assignment_counter_scratch_data()
    }

    /// Quotes formatter/hash/schema-factory work before either allocating quote.
    ///
    /// `request` is the actual bounded-input Prepare typed payload. This method
    /// observes its fields without serialization, parsing, I/O or admission.
    ///
    /// # Errors
    /// Refuses metadata overflow or a foreign emitter/actor.
    pub fn original_native_import18_prepare_quote_prewalk_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        baseline: &BeginRequest,
        request: &PacketCompleteRestorePrepareRequest,
        binding: &PacketNativeImport18Binding,
        expected_backend_schema: &SchemaRef,
    ) -> Result<(usize, usize), ProviderError> {
        self.native_import18_phase_quote_prewalk(
            emitter,
            baseline,
            request,
            binding,
            expected_backend_schema,
        )
    }

    fn native_import18_phase_quote_prewalk<T: ObserveMetadata>(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        baseline: &BeginRequest,
        request: &T,
        binding: &PacketNativeImport18Binding,
        expected_backend_schema: &SchemaRef,
    ) -> Result<(usize, usize), ProviderError> {
        emitter.authenticate_original(self)?;
        let facts = input_facts(baseline, request, binding, expected_backend_schema)?;
        let (contract, _) = native_import18_contract_storage_data(usize::MAX)?;
        Ok((
            sum(&[
                original_serialization_formatter_temporary_storage_data(&facts)?,
                contract,
                "blake3-256".len() + "cnp.blob.v1".len() + 64,
            ])?,
            Self::original_native_import18_assignment_counter_scratch_data(),
        ))
    }

    /// Quotes the actual first assignment beneath its completed Fresh query.
    ///
    /// Borrows the same retained input record later moved into the assignment;
    /// the quote cannot consume or replace its fields. The defining prewalk must
    /// be admitted before entry. This method creates no DOM, operational cut,
    /// literal slot, native permission or Source claim.
    ///
    /// # Errors
    /// Refuses a foreign/stale query, selection, invalid complete inputs, frame
    /// excess, unavailable journal/cache credit or requested-storage overflow.
    pub fn quote_original_native_import18_prepare_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        inputs: &OriginalNativeImport18PrepareInputs,
        normalization: &[u8],
        maximum: usize,
    ) -> Result<OriginalNativeImport18AssignmentStorageData, ProviderError> {
        let OriginalNativeImport18PrepareInputs {
            request_id,
            baseline,
            request,
            binding,
            expected_backend_schema,
        } = inputs;

        query.authenticate_current(self, emitter)?;
        self.session.native_import18_selection_data()?;
        let row = quote(
            self,
            inputs,
            normalization,
            maximum,
            identity(
                &(
                    request_id,
                    baseline,
                    request,
                    binding,
                    expected_backend_schema,
                    query.original_data().ok_or_else(invalid)?.sequence,
                    query.allocation_reference_data().ok_or_else(invalid)?,
                ),
                normalization,
            )?,
        )?;
        query.authenticate_current(self, emitter)?;
        Ok(row)
    }
}

fn quote(
    controller: &CnpController,
    inputs: &OriginalNativeImport18PrepareInputs,
    normalization: &[u8],
    maximum: usize,
    identity: blake3::Hash,
) -> Result<OriginalNativeImport18AssignmentStorageData, ProviderError> {
    let OriginalNativeImport18PrepareInputs {
        request_id,
        baseline,
        request,
        binding,
        expected_backend_schema,
    } = inputs;

    let phase = PacketNativeImport18Phase::Prepare;
    if controller.original_complete_restore.is_some()
        || controller.original_complete_restore_prepare.is_some()
        || controller.original_complete_restore_commit.is_some()
    {
        return Err(invalid());
    }
    let facts = input_facts(baseline, request, binding, expected_backend_schema)?;
    let shell = EnvelopeView {
        controller,
        request_id,
        baseline,
        request,
        binding,
        phase,
    };
    let data = actual_serialization_storage_data(&shell, facts, maximum)?;
    let json_profile = NativeImport18JsonMetadataProfileData::assignment_data(
        facts.observed_nodes,
        data.serialized_value_nodes,
        data.serialized_capacity_records,
    )?;
    let maximum_frame = data.maximum_encoded_bytes;
    if maximum_frame > controller.maximum_frame()? {
        return Err(credit());
    }
    let raw_response = crate::connection::original_host_initial_raw_receive_storage_data(
        controller.maximum_frame()?,
    )?;
    let outgoing_work = data.requested_total()?;
    let response_canonical =
        crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            controller.maximum_frame()?,
        )?
        .canonical_pass_requested_bytes()?;
    let cache = controller
        .custody
        .fresh_query_cache_requested_layout_data(1)?;
    let pending = crate::retained_metadata::requested_storage::tree_storage_data(
        1,
        1,
        size_of::<Id>() + size_of::<Envelope>(),
        align_of::<Id>().max(align_of::<Envelope>()),
    )?;
    let request_identity_backing = sum(&[
        request_id.as_str().len(),
        request_id.as_str().len(),
        "blake3-256".len(),
        "cnp.request.v1".len(),
        64,
    ])?;
    let input_backing = backing(&facts)?;
    let algorithm =
        crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
    let typed_proof_backing = sum(&[
        phase.payload_phase_data().proof_extension().len(),
        algorithm.len(),
        2 * 32,
    ])?;
    let typed_receipt_backing = sum(&[
        phase.payload_phase_data().receipt_extension().len(),
        algorithm.len(),
        7 * 32,
    ])?;
    let mut association = MetadataObserver::new();
    association.shared_value(controller.protocol_owner.as_ref())?;
    let shared_backing = backing(&association.finish())?;
    // Actual Source original, guard and custody request copies are independent.
    // The future response is unknown and retains raw, cached and capsule owners.
    let retained = sum(&[
        size_of::<OriginalNativeImport18Assignment>(),
        size_of::<OriginalNativeImport18AssignmentStorageData>(),
        input_backing,
        typed_proof_backing,
        typed_receipt_backing,
        shared_backing,
        shared_backing,
        normalization.len(),
        maximum_frame,
        data.retained_value_backing_bytes,
        data.retained_value_backing_bytes,
        data.retained_value_backing_bytes,
        cache,
        pending,
        request_identity_backing,
        raw_response, // Controller cache response.
        raw_response, // Capsule raw Envelope.
        raw_response, // Raw receive/literal owner.
        raw_response, // Independent retained ReceivedFrame envelope/typed cache.
    ])?;
    let (contract, _) = native_import18_contract_storage_data(maximum)?;
    // Explicit independent outgoing projection/digest/typed-guard windows and
    // ordinary full negotiated error/receive/decode/containment windows.
    // Name the actual by-value phase/capsule/Option constructor roots; these
    // are temporary owning outputs, not fixed observer scratch or a copy factor.
    let constructors = sum(&[
        size_of::<AssignedPhase<PacketCompleteRestorePrepareRequest>>(),
        size_of::<OriginalNativeImport18Assignment>(),
        size_of::<Option<OriginalNativeImport18Assignment>>(),
        size_of::<SchemaRef>(),
    ])?;
    let mut roster_observer = MetadataObserver::new();
    let roster = PacketNativeImport18InputRole::ALL.map(|role| {
        let reference = role.reference_data(request, binding);
        (role, reference, role.maximum_bytes_data(binding))
    });
    for (_, reference, _) in &roster {
        roster_observer.observe(*reference)?;
    }
    let roster_work =
        actual_serialization_storage_data(&roster, roster_observer.finish(), maximum)?;
    let transient = sum(&[
        constructors,
        size_of::<crate::transport::RetainedFrame>(),
        size_of::<Option<crate::transport::RetainedFrame>>(),
        roster_work.requested_total()?,
        raw_response, // Actual retained ReceivedFrame clone/decode window.
        size_of::<crate::connection::ReceivedFrame>(),
        size_of::<Option<crate::connection::ReceivedFrame>>(),
        size_of::<Bytes>(),
        32,
        outgoing_work,
        outgoing_work,
        outgoing_work,
        outgoing_work,
        outgoing_work,
        contract,
        response_canonical,
        raw_response,
        raw_response,
        raw_response,
    ])?;
    let scratch = CnpController::original_native_import18_assignment_counter_scratch_data();
    if sum(&[retained, transient, scratch])? > maximum {
        return Err(credit());
    }
    controller.preflight_source_reply(
        1,
        0,
        maximum_frame
            .checked_add(controller.maximum_frame()?)
            .ok_or_else(credit)?,
        0,
        0,
    )?;
    Ok(OriginalNativeImport18AssignmentStorageData {
        controller: Rc::clone(&controller.protocol_owner),
        frontier: controller.original_native5_storage_facts()?,
        phase,
        identity,
        retained,
        transient,
        scratch,
        maximum_frame,
        json_profile,
    })
}

// These are the actual emitter/current-registration controls, not a padding
// allowance or a substitute for the original owned registration gate.
fn current_guard_counter_scratch_data() -> usize {
    size_of::<&CnpController>()
        + size_of::<&OriginalCanonicalBlobAckEmitter>()
        + size_of::<&crate::handshake::ConnectionAuthority>()
        + size_of::<&crate::handshake::RegistrationRead>()
        + size_of::<crate::handshake::RegistrationRead>()
        + size_of::<Result<crate::handshake::RegistrationRead, ProviderError>>()
        + size_of::<std::sync::MutexGuard<'static, ()>>()
        + size_of::<std::sync::TryLockResult<std::sync::MutexGuard<'static, ()>>>()
        + size_of::<std::sync::TryLockError<std::sync::MutexGuard<'static, ()>>>()
        + size_of::<std::sync::atomic::Ordering>()
        + size_of::<crate::handshake::Limits>()
        + size_of::<&ProtocolCaptureOwner>()
        + size_of::<&Rc<crate::connection::Native5CodecOwner>>()
        + size_of::<Rc<dyn crate::connection::BodySchemaVerifier>>()
        + size_of::<std::thread::Thread>()
        + size_of::<std::thread::ThreadId>()
        + size_of::<u32>()
        + size_of::<OriginalProtocolStorageFacts>()
        + size_of::<Result<OriginalProtocolStorageFacts, ProviderError>>()
        + size_of::<&crate::reference_packet::control::PacketControlSelection>()
        + size_of::<Result<&crate::reference_packet::control::PacketControlSelection, ProviderError>>(
        )
        + size_of::<
            Option<crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection>,
        >()
        + size_of::<
            Result<
                Option<
                    crate::reference_packet::service::ack_emitter::PacketNative5AckEmitterSelection,
                >,
                ProviderError,
            >,
        >()
}

fn input_facts<T: ObserveMetadata>(
    baseline: &BeginRequest,
    request: &T,
    binding: &PacketNativeImport18Binding,
    expected_backend_schema: &SchemaRef,
) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
    let mut observer = MetadataObserver::new();
    observer.observe(baseline)?;
    observer.observe(request)?;
    observer.observe(binding)?;
    observer.observe(expected_backend_schema)?;
    Ok(observer.finish())
}

struct EnvelopeView<'a, T> {
    controller: &'a CnpController,
    request_id: &'a Id,
    baseline: &'a BeginRequest,
    request: &'a T,
    binding: &'a PacketNativeImport18Binding,
    phase: PacketNativeImport18Phase,
}

// Serialize the same real routing fields without cloning or constructing an
// Envelope. Proof digest strings are the exact fixed-width new-family grammar.
impl<T: Serialize> Serialize for EnvelopeView<'_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(13))?;
        map.serialize_entry("protocol", "CNP/1")?;
        map.serialize_entry("message", &MessageKind::Request)?;
        map.serialize_entry("session_id", self.controller.authority().session_id())?;
        map.serialize_entry(
            "incarnation_id",
            self.controller.authority().incarnation_id(),
        )?;
        map.serialize_entry("node_id", &self.controller.route.node)?;
        map.serialize_entry("execution_owner_id", &self.controller.route.execution_owner)?;
        map.serialize_entry("capture_owner_id", &Option::<&Id>::None)?;
        map.serialize_entry("request_id", self.request_id)?;
        map.serialize_entry("operation_id", &Option::<&Id>::None)?;
        map.serialize_entry("sequence", &U64::new(u64::MAX))?;
        map.serialize_entry("method", &Method::Begin)?;
        map.serialize_entry("body", self.baseline)?;
        map.serialize_entry("extensions", &ExtensionsView(self))?;
        map.end()
    }
}

struct ExtensionsView<'a, 'b, T>(&'a EnvelopeView<'b, T>);

impl<T: Serialize> Serialize for ExtensionsView<'_, '_, T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(self.0.phase.request_extension(), self.0.request)?;
        map.serialize_entry(NATIVE_IMPORT18_EXTENSION, self.0.binding)?;
        let proof = ProofView {
            schema: self.0.phase.payload_phase_data().proof_extension(),
            algorithm: crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM,
            context_digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            mac: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        };
        map.serialize_entry(self.0.phase.proof_extension(), &proof)?;
        map.end()
    }
}

#[derive(Serialize)]
struct ProofView {
    schema: &'static str,
    algorithm: &'static str,
    context_digest: &'static str,
    mac: &'static str,
}

struct HashWriter(blake3::Hasher);

impl std::io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn identity(value: &impl Serialize, normalization: &[u8]) -> Result<blake3::Hash, ProviderError> {
    let mut writer = HashWriter(blake3::Hasher::new_derive_key(
        "source-private.native18-sdk-input-identity/1",
    ));
    serde_json::to_writer(&mut writer, value).map_err(crucible_node_format::ContractError::from)?;
    let length = u64::try_from(normalization.len()).map_err(|_| credit())?;
    writer.0.update(&length.to_be_bytes());
    writer.0.update(normalization);
    Ok(writer.0.finalize())
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0usize, |sum, next| {
        sum.checked_add(*next).ok_or_else(credit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_input_identity_binds_every_payload_field_and_normalization_bytes() {
        let original = serde_json::json!({"whole": {"unchanged": 1}, "phase": "prepare"});
        let changed = serde_json::json!({"whole": {"unchanged": 2}, "phase": "prepare"});

        let exact = identity(&original, b"actual normalization").unwrap();
        let changed_payload = identity(&changed, b"actual normalization").unwrap();
        let changed_normalization = identity(&original, b"another normalization").unwrap();

        assert_ne!(exact, changed_payload);
        assert_ne!(exact, changed_normalization);
        assert_eq!(exact, identity(&original, b"actual normalization").unwrap());
    }
}

#[cfg(test)]
mod backend_definition_tests {
    use super::*;

    #[test]
    fn independent_full_definition_changes_identity_even_with_same_key_and_version() {
        let expected = native_import18_schema_data().unwrap();
        let mut different = expected.clone();
        different.definition =
            canonical::content_ref(b"different full definition", "application/schema+json")
                .unwrap();
        let actual = identity(&("same request", &expected), b"same normalization").unwrap();

        assert_eq!(expected.id, different.id);
        assert_eq!(expected.version, different.version);
        assert_ne!(
            actual,
            identity(&("same request", &different), b"same normalization").unwrap()
        );
    }
}

#[path = "storage/history.rs"]
mod history;
pub use history::OriginalNativeImport18AssignmentRowHistoryData;
