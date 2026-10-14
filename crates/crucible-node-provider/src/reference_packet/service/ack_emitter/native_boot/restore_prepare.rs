//! Authenticates the actual preupload request without granting memory permission.
//!
//! The SDK must separately quote and reserve the exact six input banks before
//! its owning acknowledgement can make a prepare receipt eligible. The private
//! proof token retains the actual native birth, original literal and full signed
//! selection; a portable allocation plan or transfer-token digest is insufficient.

use super::*;
#[path = "input_admission.rs"]
mod input_admission;
#[path = "prepare_receipt.rs"]
mod prepare_receipt;
use crate::reference_packet::service::NativeRestoreServiceAllocationQuote;
pub(crate) use input_admission::VerifiedCanonicalRestoreInputAdmission;

use crate::{
    bodies::{BeginArguments, RequestBody, decode_request},
    connection::{
        Connection, NativeRestoreInputAllocationQuote, OriginalCompleteRestoreInputCustody,
        OriginalNativeRestorationConnectionIdentity, ProviderStream,
    },
    reference_packet::service::complete_restore::{transfer::*, *},
    retained_metadata::{MetadataObserver, RetainedProtocolMetadataFacts},
};

pub(super) struct NativeCompleteRestorePrepareAttempt {
    creator: u32,
    thread: ThreadId,
    original: Option<Envelope>,
    service_quote: Option<NativeRestoreServiceAllocationQuote>,
    control_quote: Option<crate::reference_packet::control::PacketFreshRestoreControlAllocation>,
    realize: Option<crate::bodies::RealizeRequest>,
    receipt_started: bool,
    input_segment_issued: bool,
    input_segment_started: bool,
    receipt_result: Option<crate::bodies::PrepareRestoreResult>,
    receipt_body: Vec<u8>,
    request: Option<PacketCompleteRestorePrepareRequest>,
    proof: Option<PacketCompleteRestoreTransferProof>,
    context: Option<PacketCompleteRestorePrepareContext>,
    context_body: Vec<u8>,
    kernel: Option<serde_json::Value>,
    policy: Option<serde_json::Value>,
    transfer_token: Option<Bytes>,
    custody: Option<Rc<RefCell<OriginalCompleteRestoreInputCustody>>>,
    reactive: bool,
    verified: bool,
}

pub(crate) struct VerifiedCompleteRestorePrepare {
    identity: OriginalNativeRestorationConnectionIdentity,
    boot: Rc<RefCell<NativeAckBoot>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    authority: ConnectionAuthority,
    attempt: Rc<RefCell<NativeCompleteRestorePrepareAttempt>>,
}

impl NativeAckBoot {
    pub(crate) fn verify_complete_restore_prepare_into<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        hello: &OriginalNativeHelloJournal,
        original: &Envelope,
        connection: &Connection<S>,
        completed: &mut Option<VerifiedCompleteRestorePrepare>,
        service_quote: &mut Option<NativeRestoreServiceAllocationQuote>,
        control_quote: &mut Option<
            crate::reference_packet::control::PacketFreshRestoreControlAllocation,
        >,
    ) -> Result<(), ProviderError> {
        let admitted = connection.original_native_owned11_admission()?;
        admitted.authenticate_current(connection)?;
        if completed.is_some()
            || !Rc::ptr_eq(boot, &admitted.boot)
            || admitted.policy.complete_restore_selection()
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || admitted
                .policy
                .complete_restore_transfer_definitions()
                .is_none()
        {
            return Err(refused());
        }
        service_quote
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_original(connection, boot, &admitted.policy)?;
        control_quote
            .as_ref()
            .ok_or_else(refused)?
            .authenticate_original(&admitted.policy)?;
        let mut owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        if !owner.ready
            || !owner.verified
            || owner.transfer.is_some()
            || owner.restoration.is_some()
        {
            return Err(refused());
        }
        let attempt = Rc::new(RefCell::new(NativeCompleteRestorePrepareAttempt {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            original: None,
            service_quote: None,
            control_quote: None,
            realize: None,
            receipt_started: false,
            input_segment_issued: false,
            input_segment_started: false,
            receipt_result: None,
            receipt_body: Vec::new(),
            request: None,
            proof: None,
            context: None,
            context_body: Vec::new(),
            kernel: None,
            policy: None,
            transfer_token: None,
            custody: None,
            reactive: false,
            verified: false,
        }));
        owner.transfer = Some(Rc::clone(&attempt));
        let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.service_quote = service_quote.take();
        flight.control_quote = control_quote.take();
        flight
            .receipt_body
            .try_reserve_exact(MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)
            .map_err(|_| ProviderError::ResourceExhausted("native prepare receipt bank"))?;
        flight.original = Some(original.clone());
        // This SDK projection is syntax-only; identity below authenticates its
        // actual latest incoming literal after the independently derived MAC.
        let _projection =
            crate::connection::CompleteRestoreTransferProjection::from_envelope(original)?;
        let request = original
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
            .ok_or_else(refused)?;
        let proof = original
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION)
            .ok_or_else(refused)?;
        crate::connection::serialized_credit(
            request,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        crate::connection::serialized_credit(proof, MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?;
        flight.request = Some(
            PacketCompleteRestorePrepareRequest::deserialize(request)
                .map_err(ContractError::from)?,
        );
        flight.proof = Some(
            PacketCompleteRestoreTransferProof::deserialize(proof).map_err(ContractError::from)?,
        );
        flight
            .request
            .as_ref()
            .ok_or_else(refused)?
            .validate_data()?;
        flight
            .proof
            .as_ref()
            .ok_or_else(refused)?
            .validate_data(PacketCompleteRestoreTransferPhase::Prepare)?;
        let launch = PacketNative5SourceLaunch::decode(&owner.launch_body, 1024 * 1024)?;
        flight.realize = Some(launch.selection.realize.clone());
        flight.reactive = matches!(
            launch.program,
            crate::reference_packet::service::PacketConnectedSourceProgram::Reactive { .. }
        );
        authenticate_target(
            &launch,
            flight.request.as_ref().ok_or_else(refused)?,
            original,
            &admitted.authority,
        )?;
        let authority = &admitted.authority;
        let pair = hello.original_literal_frame_digests()?;
        let old = owner.context.as_ref().ok_or_else(refused)?;
        if blake3::Hash::from_bytes(pair.request_frame_digest) != *old.hello_request.as_slice()
            || blake3::Hash::from_bytes(pair.response_frame_digest)
                != *old.hello_response.as_slice()
            || owner.banks.iter().any(Vec::is_empty)
        {
            return Err(refused());
        }
        let host_executable = crate::conformance::measure_executable(&std::path::PathBuf::from(
            format!("/proc/{}/exe", launch.controller_pid.get()),
        ))?;
        if host_executable != owner.data.host_executable {
            return Err(refused());
        }
        let native_executable = crate::conformance::measure_executable(&std::env::current_exe()?)?;
        flight.kernel = Some(serde_json::json!({
            "schema":"source-owned.packet-canonical-ack-kernel-binding/5",
            "controller":{"pid":launch.controller_pid,"uid":launch.controller_uid,"executable":host_executable},
            "native":{"pid":U64::new(u64::from(std::process::id())),
                "uid":U64::new(u64::from(rustix::process::geteuid().as_raw())),"executable":native_executable}
        }));
        let extensions = authority.selected_extensions().ok_or_else(refused)?;
        flight.policy = Some(serde_json::json!({
            "schema":"source-owned.packet-canonical-ack-policy-binding/5",
            "source_binding":owner.data.source_birth,
            "negotiated":{"limits":authority.limits(),"features":authority.selected_features(),
                "extensions":extensions,"envelope_extensions":authority.envelope_extensions()}
        }));
        if flight.kernel.as_ref() != owner.normalized[1].as_ref()
            || flight.policy.as_ref() != owner.normalized[2].as_ref()
        {
            return Err(refused());
        }
        let maximum =
            usize::try_from(authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        let request = flight.request.as_ref().ok_or_else(refused)?;
        let input_roster = request.input_roster_digest_data()?;
        let request_body = canonical::canonical_json(
            &serde_json::to_value(request).map_err(ContractError::from)?,
        )?;
        flight.context = Some(PacketCompleteRestorePrepareContext {
            schema: "source-owned.packet-complete-restore-prepare-context/12".into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            source_birth: digest(&owner.banks[0]),
            kernel_binding: digest(&owner.banks[1]),
            policy_binding: digest(&owner.banks[2]),
            host_registration: digest(&owner.host_body),
            native_registration: digest(&owner.banks[3]),
            hello_request: Bytes::new(pair.request_frame_digest.to_vec()),
            hello_response: Bytes::new(pair.response_frame_digest.to_vec()),
            assigned_prepare: Bytes::new(
                complete_restore_transfer_assigned_request_digest(
                    original,
                    PacketCompleteRestoreTransferPhase::Prepare,
                    maximum,
                )?
                .to_vec(),
            ),
            prepare_request: digest(&request_body),
            input_roster,
        });
        let context = flight.context.as_ref().ok_or_else(refused)?;
        context.authenticate_request_data(flight.request.as_ref().ok_or_else(refused)?)?;
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        verify_complete_restore_prepare_proof_data(
            key,
            context,
            flight.proof.as_ref().ok_or_else(refused)?,
        )?;
        flight.context_body = canonical::canonical_json(
            &serde_json::to_value(context).map_err(ContractError::from)?,
        )?;
        if flight.context_body.len() > MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES {
            return Err(refused());
        }
        let derived = blake3::derive_key(
            "source-owned.packet-complete-restore-transfer-token-key/12",
            key,
        );
        flight.transfer_token = Some(Bytes::new(
            blake3::keyed_hash(&derived, &flight.context_body)
                .as_bytes()
                .to_vec(),
        ));
        owner.ensure_origin()?;
        authority.ensure_live()?;
        let identity =
            connection.retain_original_native_restore_identity(original, &admitted.policy)?;
        identity.authenticate_installation(connection, original)?;
        flight.verified = true;
        drop(flight);
        *completed = Some(VerifiedCompleteRestorePrepare {
            identity,
            boot: Rc::clone(boot),
            policy: Rc::clone(&admitted.policy),
            authority: authority.clone(),
            attempt: Rc::clone(&attempt),
        });
        Ok(())
    }
}

impl VerifiedCompleteRestorePrepare {
    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.identity.authenticate_current(connection)?;
        self.authority.ensure_live()?;
        let boot = self.boot.try_borrow().map_err(|_| borrowed())?;
        boot.ensure_origin()?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !boot.verified
            || !flight.verified
            || boot
                .policy
                .as_ref()
                .is_none_or(|policy| !Rc::ptr_eq(policy, &self.policy))
            || boot
                .transfer
                .as_ref()
                .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
            || flight.original.is_none()
            || flight.request.is_none()
            || flight.proof.is_none()
            || flight.context.is_none()
            || flight.transfer_token.is_none()
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn authenticate_installation<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        self.identity
            .authenticate_installation(connection, flight.original.as_ref().ok_or_else(refused)?)
    }

    pub(crate) fn request<'a, S: ProviderStream>(
        &'a self,
        connection: &Connection<S>,
    ) -> Result<std::cell::Ref<'a, PacketCompleteRestorePrepareRequest>, ProviderError> {
        self.authenticate_current(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        std::cell::Ref::filter_map(flight, |flight| flight.request.as_ref()).map_err(|_| refused())
    }

    pub(crate) fn original_prepare_result_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &crate::reference_packet::control::PacketControl,
    ) -> Result<crate::bodies::PrepareRestoreResult, ProviderError> {
        self.authenticate_installation(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        control.original_restore_prepare_result_data(
            flight.control_quote.as_ref().ok_or_else(refused)?,
            flight.request.as_ref().ok_or_else(refused)?,
        )
    }

    pub(crate) fn authenticate_input_allocation<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        quote: &NativeRestoreInputAllocationQuote,
    ) -> Result<(), ProviderError> {
        self.authenticate_installation(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        let request = flight.request.as_ref().ok_or_else(refused)?;
        quote.authenticate_original_request(request)?;
        let quote_owner = flight.service_quote.as_ref().ok_or_else(refused)?;
        quote_owner.authenticate_original(connection, &self.boot, &self.policy)?;
        let mut observer = MetadataObserver::new();
        self.identity.observe_retained_metadata(&mut observer)?;
        self.authority.observe_retained_metadata(&mut observer)?;
        observer.shared_value(self.attempt.as_ref())?;
        flight.observe_actual_retained_metadata(&mut observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativeBoot,
            self.boot.as_ref(),
        )?;
        self.boot
            .try_borrow()
            .map_err(|_| borrowed())?
            .observe_admitted_boot_metadata(&mut observer)?;
        observer.shared_original(
            crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
            self.policy.as_ref(),
        )?;
        self.policy.observe_owned11_metadata(&mut observer)?;
        let control_quote = flight.control_quote.as_ref().ok_or_else(refused)?;
        control_quote.authenticate_original(&self.policy)?;
        let endpoint_backing = known_backing_bytes(control_quote.endpoint_facts())?;
        let control_backing = known_backing_bytes(control_quote.facts())?;
        let dynamic = known_backing_bytes(observer.finish())?
            .checked_add(known_backing_bytes(quote_owner.retained_facts())?)
            .and_then(|bytes| bytes.checked_add(control_backing))
            .and_then(|bytes| bytes.checked_add(endpoint_backing))
            .ok_or_else(refused)?;
        let model_header = if flight.reactive {
            std::mem::size_of::<crate::reference_packet::connected::PacketReactiveModelAdoption>()
        } else {
            std::mem::size_of::<
                crate::reference_packet::continuation_models::PacketProducerModelAdoption,
            >()
        };
        let fixed = std::mem::size_of::<NativeCompleteRestorePrepareAttempt>()
            .checked_add(std::mem::size_of::<
                crate::reference_packet::control::PacketControl,
            >())
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    crate::reference_packet::control::PacketFreshRestoreControlAllocation,
                >())
            })
            .and_then(|bytes| bytes.checked_add(control_quote.endpoint_header_bytes()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(model_header))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<NativeRestoreServiceAllocationQuote>())
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<
                    crate::reference_packet::control::PacketDecodedControlSnapshot,
                >())
            })
            .and_then(|bytes| bytes.checked_add(dynamic))
            .ok_or_else(refused)?;
        let model_bound =
            usize::try_from(request.allocation.maximum_model_bytes.get()).map_err(|_| refused())?;
        // This is a signed domain budget. After upload, actual projection and
        // displacement demand must also fit it before any reconstruction/effect.
        quote.conjoin_native_allocation_data(request, fixed, model_bound)
    }

    pub(crate) fn attach_input_custody<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        custody: &Rc<RefCell<OriginalCompleteRestoreInputCustody>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_installation(connection)?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        if let Some(original) = &flight.custody {
            return if Rc::ptr_eq(original, custody) {
                Ok(())
            } else {
                Err(refused())
            };
        }
        flight.custody = Some(Rc::clone(custody));
        Ok(())
    }
}

impl NativeCompleteRestorePrepareAttempt {
    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }

    fn observe_actual_retained_metadata(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        observer.observe(&self.realize)?;
        observer.observe(&self.receipt_body)?;
        if let Some(result) = &self.receipt_result {
            observer.observe(&result.transaction_id)?;
            observer.observe(&result.prepared_token)?;
            observer.observe(&result.world_binding_hash)?;
            observer.observe(&result.owner_binding_hash)?;
            observer.observe(&result.staged_owner_ids)?;
            observer.observe(&result.closed_gate_receipt)?;
            observer.observe(&result.validated_manifest)?;
        }
        observer.observe(&self.original)?;
        observer.observe(&self.kernel)?;
        observer.observe(&self.policy)?;
        observer.observe(&self.context_body)?;
        observer.observe(&self.transfer_token)?;
        let request = self.request.as_ref().ok_or_else(refused)?;
        let PacketCompleteRestorePrepareRequest {
            schema,
            restoration,
            host_protocol,
            native_protocol,
            native_control,
            native_anchor,
            transaction_id,
            generation: _,
            allocation: _,
        } = request;
        observer.observe(schema)?;
        for reference in [
            host_protocol,
            native_protocol,
            native_control,
            native_anchor,
        ] {
            observer.observe(reference)?;
        }
        observer.observe(transaction_id)?;
        let PacketCompleteRestoreRequest {
            schema,
            archive_index,
            capture_manifest,
            owner_state,
            journal,
            source_runtime,
            backend_implementation,
            backend_schema,
            archived_cut: _,
            archived_ordinal: _,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation: _,
            target_owner_generation: _,
            mapping,
            nonce,
        } = restoration;
        observer.observe(schema)?;
        for reference in [
            archive_index,
            capture_manifest,
            owner_state,
            journal,
            source_runtime,
            backend_implementation,
            mapping,
        ] {
            observer.observe(reference)?;
        }
        observer.observe(backend_schema)?;
        observer.observe(target_world)?;
        observer.observe(target_owner)?;
        observer.observe(target_owner_binding)?;
        observer.observe(target_activation)?;
        observer.observe(nonce)?;
        let PacketCompleteRestoreTransferProof {
            schema,
            algorithm,
            context_digest,
            mac,
        } = self.proof.as_ref().ok_or_else(refused)?;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(context_digest)?;
        observer.observe(mac)?;
        let PacketCompleteRestorePrepareContext {
            schema,
            algorithm,
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_prepare,
            prepare_request,
            input_roster,
        } = self.context.as_ref().ok_or_else(refused)?;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        for value in [
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_prepare,
            prepare_request,
            input_roster,
        ] {
            observer.observe(value)?;
        }
        Ok(())
    }
}

pub(super) fn known_backing_bytes(
    facts: RetainedProtocolMetadataFacts,
) -> Result<usize, ProviderError> {
    let trees = retained_tree_storage(facts)?;
    let shared_headers = retained_shared_header_storage(facts)?;
    facts
        .string_capacity_bytes
        .checked_add(facts.vector_capacity_bytes)
        .and_then(|bytes| bytes.checked_add(facts.boxed_value_bytes))
        .and_then(|bytes| bytes.checked_add(facts.shared_value_bytes))
        .and_then(|bytes| bytes.checked_add(trees))
        .and_then(|bytes| bytes.checked_add(shared_headers))
        .ok_or_else(refused)
}

// Source-pinned Rust 1.98.1 B=6 requested-layout bound, matching the SDK
// historical quote. Empty retained trees may own roots, and each observed view
// is charged independently. This does not pretend entry bytes are node bytes.
fn retained_tree_storage(facts: RetainedProtocolMetadataFacts) -> Result<usize, ProviderError> {
    let alignment = facts
        .maximum_tree_entry_alignment
        .max(std::mem::align_of::<usize>());
    std::alloc::Layout::from_size_align(0, alignment).map_err(|_| refused())?;
    let words = std::mem::size_of::<usize>();
    let node = words
        .checked_add(2 * std::mem::size_of::<u16>())
        .and_then(|bytes| bytes.checked_add(12 * words))
        .and_then(|bytes| {
            facts
                .maximum_tree_key_value_bytes
                .checked_mul(11)
                .and_then(|entries| bytes.checked_add(entries))
        })
        .and_then(|bytes| {
            (alignment - 1)
                .checked_mul(8)
                .and_then(|padding| bytes.checked_add(padding))
        })
        .ok_or_else(refused)?;
    facts
        .tree_containers
        .checked_add(facts.tree_entries)
        .and_then(|nodes| nodes.checked_mul(node))
        .ok_or_else(refused)
}

fn retained_shared_header_storage(
    facts: RetainedProtocolMetadataFacts,
) -> Result<usize, ProviderError> {
    let alignment = facts
        .maximum_shared_value_alignment
        .max(std::mem::align_of::<usize>());
    std::alloc::Layout::from_size_align(0, alignment).map_err(|_| refused())?;
    let base = (2 * std::mem::size_of::<usize>())
        .checked_add(alignment - 1)
        .map(|bytes| bytes & !(alignment - 1))
        .ok_or_else(refused)?;
    base.checked_add(alignment - 1)
        .and_then(|header| facts.shared_backing_views.checked_mul(header))
        .ok_or_else(refused)
}

pub(super) fn authenticate_target(
    launch: &PacketNative5SourceLaunch,
    request: &PacketCompleteRestorePrepareRequest,
    original: &Envelope,
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    let binding = launch
        .selection
        .realization
        .bindings
        .first()
        .ok_or_else(refused)?;
    let owner = launch
        .selection
        .realization
        .owner_bindings
        .first()
        .ok_or_else(refused)?;
    let RequestBody::Begin(begin) = decode_request(original.method, &original.body)? else {
        return Err(refused());
    };
    let BeginArguments::PrepareRestore(arguments) = begin.decoded_arguments()? else {
        return Err(refused());
    };
    let coordinator =
        crate::reference_packet::coordinator::PacketNative5CoordinatorInstallation::decode(
            launch.initial_coordinator.bytes.as_slice(),
            &launch.selection,
        )?;
    let activation = &coordinator.template["activation"];
    let target = &request.restoration;
    if launch.complete_restore_selection
        != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.capture_owner_id.0.as_ref() != Some(&owner.owner.id)
        || original.execution_owner_id.0.is_some()
        || original.operation_id.0.is_none()
        || target.target_world != launch.selection.world
        || target.target_owner != owner.owner.id
        || target.target_owner_binding != owner.identity()?
        || target.target_owner_generation != binding.authority.owner_generation
        || serde_json::to_value(&target.target_activation).map_err(ContractError::from)?
            != activation["activation_id"]
        || serde_json::to_value(target.target_generation).map_err(ContractError::from)?
            != activation["generation"]
        || begin.binding_hash != target.target_owner_binding
        || begin.activation_id.0.as_ref() != Some(&target.target_activation)
        || begin.world_generation != target.target_generation
        || begin.owner_generation != target.target_owner_generation
        || !begin.extensions.is_empty()
        || arguments.transaction_id != request.transaction_id
        || arguments.capture_manifest != target.capture_manifest
        || arguments.expected_world_binding_hash != target.target_world
        || arguments.expected_owner_binding_hash != target.target_owner_binding
        || arguments.destination_owner_ids.len() != 1
        || arguments.destination_owner_ids.first() != Some(&target.target_owner)
    {
        return Err(refused());
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Bytes {
    Bytes::new(blake3::hash(bytes).as_bytes().to_vec())
}
fn refused() -> ProviderError {
    ProviderError::Correlation("fresh original complete restore prepare differs")
}
fn borrowed() -> ProviderError {
    ProviderError::Conflict("fresh original complete restore prepare borrowed")
}

// crucible-lint: allow panic-shortcut -- Allocation-bound controls use assertion verdicts.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod allocation_geometry_tests {
    use super::*;

    #[test]
    fn retained_empty_tree_root_remains_charged_after_entry_removal() {
        let mut object = serde_json::Map::new();
        object.insert("retained".into(), serde_json::Value::Bool(true));
        object.remove("retained");
        let value = serde_json::Value::Object(object);
        let mut observer = MetadataObserver::new();
        observer.observe(&value).unwrap();
        let facts = observer.finish();
        assert_eq!(facts.tree_entries, 0);
        assert_eq!(facts.tree_containers, 1);
        assert!(known_backing_bytes(facts).unwrap() > 0);
    }

    #[test]
    fn retained_shared_alignment_and_overflow_are_not_zero_cost() {
        #[repr(align(256))]
        struct Aligned([u8; 256]);
        let payload = Rc::new(Aligned([0; 256]));
        let mut observer = MetadataObserver::new();
        observer.shared_value(payload.as_ref()).unwrap();
        let facts = observer.finish();
        assert_eq!(facts.maximum_shared_value_alignment, 256);
        assert!(known_backing_bytes(facts).unwrap() > payload.0.len());
        let overflow = RetainedProtocolMetadataFacts {
            tree_containers: usize::MAX,
            tree_entries: 1,
            ..facts
        };
        assert!(known_backing_bytes(overflow).is_err());
    }
}
