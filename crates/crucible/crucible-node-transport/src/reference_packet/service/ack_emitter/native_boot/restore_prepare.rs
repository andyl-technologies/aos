//! Authenticates the actual preupload request without granting memory permission.
//!
//! The SDK must separately quote and reserve the exact six input banks before
//! its owning acknowledgement can make a prepare receipt eligible. The private
//! proof token retains the actual native birth, original literal and full signed
//! selection; a portable allocation plan or transfer-token digest is insufficient.

use super::*;
#[path = "input_admission.rs"]
mod input_admission;
#[path = "prepare_bindings.rs"]
mod prepare_bindings;
#[path = "prepare_startup.rs"]
mod prepare_startup;
pub(crate) use prepare_startup::OriginalNativePrepareStartupAllocation;
pub use prepare_startup::{
    PacketNativePrepareStartupStorageData, original_native_prepare_startup_counter_scratch_data,
    original_native_prepare_startup_storage_data,
};
#[path = "prepare_context.rs"]
mod prepare_context;
#[path = "prepare_measurement.rs"]
mod prepare_measurement;
// Selected baseline birth reuses the same reviewed streamed measurement body.
pub(crate) use prepare_measurement::{
    measure_conformance_executable as measure_conformance_executable_data,
    measure_executable as measure_original_prepare_executable_data,
    original_conformance_executable_measurement_counter_scratch_data,
    original_prepare_executable_measurement_construction_data,
    original_prepare_executable_measurement_counter_scratch_data,
    original_prepare_executable_reference_retained_backing_data,
};
pub(in crate::reference_packet::service::ack_emitter::native_boot) use prepare_measurement::{
    measure_controller_executable as measure_original_restore_controller_executable,
    measure_current_executable as measure_original_restore_current_executable,
};
#[path = "prepare_target.rs"]
mod prepare_target;
pub(super) use prepare_target::authenticate_target;
#[path = "prepare_receipt.rs"]
mod prepare_receipt;
#[path = "selected_native.rs"]
mod selected_native;
use crate::reference_packet::service::NativeRestoreServiceAllocationQuote;
use crate::reference_packet::service::fresh_restore_allocation::{
    PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING, PacketNative5FreshRestoreAllocationSelection,
};
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
        Self::authenticate_legacy_prepare_startup_data(boot)?;
        Self::verify_complete_restore_prepare_with_startup_into(
            boot,
            hello,
            original,
            connection,
            None,
            completed,
            service_quote,
            control_quote,
        )
    }

    pub(crate) fn authenticate_legacy_prepare_startup_data(
        boot: &Rc<RefCell<Self>>,
    ) -> Result<(), ProviderError> {
        let owner = boot.try_borrow().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        if owner.startup.is_some() {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn verify_complete_restore_prepare_with_startup_into<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        hello: &OriginalNativeHelloJournal,
        original: &Envelope,
        connection: &Connection<S>,
        startup: Option<&OriginalNativePrepareStartupAllocation>,
        completed: &mut Option<VerifiedCompleteRestorePrepare>,
        service_quote: &mut Option<NativeRestoreServiceAllocationQuote>,
        control_quote: &mut Option<
            crate::reference_packet::control::PacketFreshRestoreControlAllocation,
        >,
    ) -> Result<(), ProviderError> {
        match startup {
            Some(startup) => startup.authenticate_header(connection, original)?,
            None => Self::authenticate_legacy_prepare_startup_data(boot)?,
        }
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
            connection.original_selected_restore_transfer_projection_data(original)?;
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
        let launch = decode_verified_prepare_launch(&owner)?;
        flight.realize = Some(launch.selection.realize.clone());
        flight.reactive = matches!(
            launch.program,
            crate::reference_packet::service::PacketConnectedSourceProgram::Reactive { .. }
        );
        prepare_target::authenticate_verified_prepare_target(
            &owner,
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
        let host_executable =
            prepare_measurement::measure_controller_executable(launch.controller_pid)?;
        if host_executable != owner.data.host_executable {
            return Err(refused());
        }
        let native_executable = prepare_measurement::measure_current_executable()?;
        // Authenticate every current binding against the original admitted
        // boot values without constructing a second kernel/source-policy DOM.
        // These attempt slots remain empty; neither slot is a proof predicate.
        prepare_bindings::authenticate_kernel_data(
            owner.normalized[1].as_ref().ok_or_else(refused)?,
            launch.controller_pid,
            launch.controller_uid,
            &host_executable,
            &native_executable,
        )?;
        prepare_bindings::authenticate_policy_data(
            owner.normalized[2].as_ref().ok_or_else(refused)?,
            &owner.data.source_birth,
            &admitted.authority,
        )?;
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
                if admitted.policy.fresh_restore_allocation_selection()
                    == Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
                    && original
                        .extensions
                        .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
                {
                    complete_restore_fresh_prepare_assigned_request_digest(original, maximum)?
                } else {
                    complete_restore_transfer_assigned_request_digest(
                        original,
                        PacketCompleteRestoreTransferPhase::Prepare,
                        maximum,
                    )?
                }
                .to_vec(),
            ),
            prepare_request: digest(&request_body),
            input_roster,
        });
        let context = flight.context.as_ref().ok_or_else(refused)?;
        // This private context was constructed immediately above from this
        // validated request's exact canonical bytes and input-roster digest.
        // Verify the native MAC over that SAME one canonical context bank.
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        flight.context_body = prepare_context::authenticate_derived_context_data(
            key,
            context,
            flight.proof.as_ref().ok_or_else(refused)?,
        )?;
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

    /// Compares the actual verified issuer original without decoding a label.
    pub(crate) fn authenticate_handoff_original_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.authenticate_verified_metadata_data()?;
        if flight.original.as_ref() != Some(original) {
            return Err(refused());
        }
        Ok(())
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
        let startup = self
            .boot
            .try_borrow()
            .map_err(|_| borrowed())?
            .requires_startup_codec_data()?;
        if startup {
            let mut roots = crate::retained_metadata::NativeCaptureMetadataRoots::new();
            if !roots.observe_shared(
                &mut observer,
                crate::retained_metadata::aliases::MetadataSharedKind::NativeRestorePrepareAttempt,
                self.attempt.as_ref(),
            )? {
                return Err(refused());
            }
            flight.observe_actual_retained_metadata(&mut observer)?;
            if roots.observe_shared(
                &mut observer,
                crate::retained_metadata::aliases::MetadataSharedKind::NativeBoot,
                self.boot.as_ref(),
            )? {
                self.boot
                    .try_borrow()
                    .map_err(|_| borrowed())?
                    .observe_verified_startup_prepare_metadata(
                        &self.attempt,
                        &mut roots,
                        &mut observer,
                    )?;
            }
            if roots.observe_shared(
                &mut observer,
                crate::retained_metadata::aliases::MetadataSharedKind::NativePolicy,
                self.policy.as_ref(),
            )? {
                self.policy
                    .observe_unique_capture_metadata(&mut roots, &mut observer)?;
            }
            roots.finish()?;
        } else {
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
        }
        let control_quote = flight.control_quote.as_ref().ok_or_else(refused)?;
        control_quote.authenticate_original(&self.policy)?;
        let endpoint_backing = if startup {
            known_backing_bytes(control_quote.endpoint_facts())?
                .checked_add(control_quote.startup_endpoint_reserved_bytes_data()?)
                .ok_or_else(refused)?
        } else {
            known_backing_bytes(control_quote.endpoint_facts())?
        };
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

    pub(super) fn authenticate_verified_metadata_data(&self) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        if !self.verified
            || self.request.is_none()
            || self.proof.is_none()
            || self.context.is_none()
            || self.transfer_token.is_none()
        {
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

/// Reuses the immutable birth validation completed by this same verified ACK.
///
/// Boot's launch_body is assigned once by prepare_into and is private to the
/// boot family. verify_admit fully decodes and validates those SAME bytes before
/// it can set verified. No method replaces or edits that bank afterward. This
/// avoids rebuilding every selected schema/contract at each Prepare; bounded
/// duplicate-refusing parsing and owned typed decode remain charged phases.
fn decode_verified_prepare_launch(
    owner: &NativeAckBoot,
) -> Result<PacketNative5SourceLaunch, ProviderError> {
    owner.ensure_origin()?;
    if !owner.ready
        || !owner.verified
        || owner.original.is_none()
        || owner.context.is_none()
        || owner.proof.is_none()
    {
        return Err(refused());
    }
    let value = canonical::parse_json(owner.original_verified_launch_literal_data()?, 1024 * 1024)?;
    PacketNative5SourceLaunch::deserialize(value)
        .map_err(ContractError::from)
        .map_err(Into::into)
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

#[path = "restore_prepare/settled_current.rs"]
mod settled_current;

pub(crate) use prepare_startup::HistoricalPrepareStartupAllocation17;

#[path = "restore_prepare/settled_token.rs"]
mod settled_token_history;
