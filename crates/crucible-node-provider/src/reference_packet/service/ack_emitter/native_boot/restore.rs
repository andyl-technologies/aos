//! Verifies the actual selected two-phase Commit before installing a fresh owner.
//!
//! The retired private single-phase issuer is absent. Old edition-eleven data
//! still decodes, but it cannot enter this selected transfer-twelve native path.
//! The actual boot owns every partial attempt before decode, MAC or model work.

use super::*;
use crate::{
    connection::{Connection, OriginalNativeRestorationConnectionIdentity, ProviderStream},
    protocol_snapshot::PreparedArchivedNativeProtocolMapping,
    reference_packet::{
        control::{
            PacketCompleteRestorePhysicalHold, PacketControl, PacketDecodedControlSnapshot,
            PacketPreparedCompleteModel,
        },
        service::complete_restore::{transfer::*, *},
    },
};

pub(super) struct NativeCompleteRestoreAttempt {
    creator: u32,
    thread: ThreadId,
    original: Option<Envelope>,
    launch: Option<PacketNative5SourceLaunch>,
    mapping: Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    host_authority: Option<serde_json::Value>,
    kernel_binding: Option<serde_json::Value>,
    policy_binding: Option<serde_json::Value>,
    request: Option<PacketCompleteRestoreCommitRequest>,
    proof: Option<PacketCompleteRestoreTransferProof>,
    context: Option<PacketCompleteRestoreCommitContext>,
    capture_request: Option<Envelope>,
    pending_control: Option<PacketDecodedControlSnapshot>,
    prepared_model: Option<PacketPreparedCompleteModel>,
    physical_hold: Option<Rc<PacketCompleteRestorePhysicalHold>>,
    gate_evidence: Option<(ContentRef, Vec<u8>)>,
    gate_data: Option<PacketNativeRestoredCommitHold>,
    receipt_body: Vec<u8>,
    receipt_result: Option<crate::bodies::PrepareRestoreResult>,
    receipt_started: bool,
    completed_response: Option<ContentRef>,
    response_body: Vec<u8>,
    requested_model_bytes: usize,
    verified: bool,
    installation_started: bool,
}

pub(crate) struct OriginalCompleteRestoreCommit<'a> {
    pub(crate) hello: &'a OriginalNativeHelloJournal,
    pub(crate) original: &'a Envelope,
    pub(crate) mapping: &'a Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    pub(crate) connection: &'a Connection<crate::client::DeadlineStream>,
    pub(crate) control: &'a PacketControl,
}

/// Binds one verified Commit to its same fresh actor and sealed historical map.
pub(crate) struct VerifiedCompleteRestoration {
    identity: OriginalNativeRestorationConnectionIdentity,
    boot: Rc<RefCell<NativeAckBoot>>,
    policy: Rc<crate::reference_packet::Native5Policy>,
    authority: ConnectionAuthority,
    attempt: Rc<RefCell<NativeCompleteRestoreAttempt>>,
}

/// Retains successful same-socket model installation and its independent hold.
pub(crate) struct VerifiedCompleteRestorationHeld {
    boot: Rc<RefCell<NativeAckBoot>>,
    mapping: Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    attempt: Rc<RefCell<NativeCompleteRestoreAttempt>>,
    hold: Rc<PacketCompleteRestorePhysicalHold>,
}

#[path = "restore_construction.rs"]
mod construction;
pub use construction::{
    PacketNativeRestoreCommitConstructionData, PacketNativeRestoreCommitConstructionInputs,
    original_native_restore_commit_construction_counter_scratch_data,
    original_native_restore_commit_construction_storage_data,
};

#[path = "restore_canonical.rs"]
mod canonical_encoding;
use canonical_encoding::bounded_canonical;

#[path = "restore_held.rs"]
mod held;
pub(crate) use held::NativeRestoredControlEvidence;
use held::prepare_gate_evidence;

#[path = "restore/settled_tokens17.rs"]
mod settled_tokens17;
pub(crate) use settled_tokens17::{HistoricalCommitToken17, HistoricalHeldToken17};

#[path = "restoration_activation.rs"]
mod restoration_activation;
pub(crate) use restoration_activation::{
    NativeRestorationActivationAttempt, NativeRestorationObservationAttempt,
    NativeRestorationUploadAttempt, OriginalRestorationActivationPermit,
    OriginalRestorationActivationRequirement, OriginalRestorationObservationPermit,
    OriginalRestorationObservationRead, OriginalRestorationReleaseState,
    OriginalRestorationReleased, OriginalRestorationUploadPermit,
    OriginalRestoredSuffixPostObservation,
    original_native_restoration_activation_attempt_backing_data,
    original_native_restoration_activation_counter_scratch_data,
    original_native_restoration_activation_ingress_row_data,
    original_native_restoration_activation_ingress_storage_data,
    original_native_restoration_observation_attempt_backing_data,
    original_native_restoration_observation_counter_scratch_data,
    original_native_restoration_observation_ingress_row_data,
    original_native_restoration_upload_attempt_backing_data,
    original_native_restoration_upload_counter_scratch_data,
    original_restored_suffix_post_observation_counter_scratch_data,
};

impl NativeAckBoot {
    pub(crate) fn verify_complete_restore_commit_into(
        boot: &Rc<RefCell<Self>>,
        input: OriginalCompleteRestoreCommit<'_>,
        completed: &mut Option<VerifiedCompleteRestoration>,
    ) -> Result<(), ProviderError> {
        let OriginalCompleteRestoreCommit {
            hello,
            original,
            mapping,
            connection,
            control,
        } = input;
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        if completed.is_some()
            || !Rc::ptr_eq(boot, &admission.boot)
            || admission.policy.complete_restore_selection()
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || admission.policy.complete_restore_definitions().is_none()
            || admission
                .policy
                .complete_restore_transfer_definitions()
                .is_none()
        {
            return Err(refused());
        }
        let policy = &admission.policy;
        let authority = &admission.authority;
        let mut owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        if !owner.ready
            || !owner.verified
            || owner.transfer.is_none()
            || owner.restoration.is_some()
        {
            return Err(refused());
        }
        let crate::connection::CompleteRestoreTransferProjection::Request {
            phase: PacketCompleteRestoreTransferPhase::Commit,
            request: borrowed_request,
            ..
        } = crate::connection::CompleteRestoreTransferProjection::from_envelope(original)?
        else {
            return Err(refused());
        };
        let maximum =
            U64::deserialize(&borrowed_request["prepare"]["allocation"]["maximum_model_bytes"])
                .map_err(ContractError::from)?
                .get();
        let maximum = usize::try_from(maximum).map_err(|_| refused())?;
        let requested_model_bytes = quoted_commit_decode_storage(original, &owner, maximum)?;
        let attempt = Rc::new(RefCell::new(NativeCompleteRestoreAttempt {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            original: None,
            launch: None,
            mapping: Rc::clone(mapping),
            host_authority: None,
            kernel_binding: None,
            policy_binding: None,
            request: None,
            proof: None,
            context: None,
            capture_request: None,
            pending_control: None,
            prepared_model: None,
            physical_hold: None,
            gate_evidence: None,
            gate_data: None,
            receipt_body: Vec::new(),
            receipt_result: None,
            receipt_started: false,
            completed_response: None,
            response_body: Vec::new(),
            requested_model_bytes,
            verified: false,
            installation_started: false,
        }));
        owner.restoration = Some(Rc::clone(&attempt));
        let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.original = Some(original.clone());
        flight.launch = Some(PacketNative5SourceLaunch::decode(
            owner.original_verified_launch_literal_data()?,
            1024 * 1024,
        )?);
        let crate::connection::CompleteRestoreTransferProjection::Request {
            phase: PacketCompleteRestoreTransferPhase::Commit,
            request,
            proof,
        } = crate::connection::CompleteRestoreTransferProjection::from_envelope(original)?
        else {
            return Err(refused());
        };
        crate::connection::serialized_credit(
            request,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        crate::connection::serialized_credit(proof, MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES)?;
        flight.request = Some(
            PacketCompleteRestoreCommitRequest::deserialize(request)
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
            .validate_data(PacketCompleteRestoreTransferPhase::Commit)?;
        // Drop the boot before asking the SDK to authenticate its actual Prepare
        // token. That token's currentness check borrows this same boot RefCell.
        drop(flight);
        drop(owner);
        {
            let flight = attempt.try_borrow().map_err(|_| borrowed())?;
            connection.authenticate_original_complete_restore_prepare_data(
                flight.request.as_ref().ok_or_else(refused)?,
            )?;
        }
        let owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
        let mapping_data = mapping.try_borrow().map_err(|_| borrowed())?;
        connection.authenticate_archived_native_protocol_mapping(&mapping_data)?;
        flight.host_authority = Some(canonical::parse_json(
            mapping_data.host_authority_projection()?,
            65_536,
        )?);
        authenticate_host_projection(
            flight.host_authority.as_ref().ok_or_else(refused)?,
            &owner.data.expected_host_registration,
        )?;
        super::restore_prepare::authenticate_target(
            flight.launch.as_ref().ok_or_else(refused)?,
            &flight.request.as_ref().ok_or_else(refused)?.prepare,
            original,
            authority,
        )?;
        let request = flight.request.as_ref().ok_or_else(refused)?;
        let target = &request.prepare.restoration;
        if &target.mapping != mapping_data.mapping_reference()
            || target.nonce.as_slice() != mapping_data.nonce()
        {
            return Err(refused());
        }
        let bindings = target.context_bindings(mapping_data.normalization_bytes())?;
        let pair = hello.original_literal_frame_digests()?;
        let admitted = owner.context.as_ref().ok_or_else(refused)?;
        if blake3::Hash::from_bytes(pair.request_frame_digest) != *admitted.hello_request.as_slice()
            || blake3::Hash::from_bytes(pair.response_frame_digest)
                != *admitted.hello_response.as_slice()
            || owner.banks.iter().any(Vec::is_empty)
        {
            return Err(refused());
        }
        let launch = flight.launch.as_ref().ok_or_else(refused)?;
        let host_executable =
            super::restore_prepare::measure_original_restore_controller_executable(
                launch.controller_pid,
            )?;
        if host_executable != owner.data.host_executable {
            return Err(refused());
        }
        let native_executable =
            super::restore_prepare::measure_original_restore_current_executable()?;
        flight.kernel_binding = Some(serde_json::json!({
            "schema":"source-owned.packet-canonical-ack-kernel-binding/5",
            "controller":{"pid":launch.controller_pid,"uid":launch.controller_uid,"executable":host_executable},
            "native":{"pid":U64::new(u64::from(std::process::id())),
                "uid":U64::new(u64::from(rustix::process::geteuid().as_raw())),"executable":native_executable}
        }));
        flight.policy_binding = Some(serde_json::json!({
            "schema":"source-owned.packet-canonical-ack-policy-binding/5",
            "source_binding":owner.data.source_birth,
            "negotiated":{"limits":authority.limits(),"features":authority.selected_features(),
                "extensions":authority.selected_extensions().ok_or_else(refused)?,
                "envelope_extensions":authority.envelope_extensions()}
        }));
        if owner.normalized[1].as_ref() != flight.kernel_binding.as_ref()
            || owner.normalized[2].as_ref() != flight.policy_binding.as_ref()
        {
            return Err(refused());
        }
        let maximum =
            usize::try_from(authority.limits().frame_bytes.get()).map_err(|_| refused())?;
        let request = flight.request.as_ref().ok_or_else(refused)?;
        let context = PacketCompleteRestoreContext {
            schema: PACKET_COMPLETE_RESTORE_CONTEXT_SCHEMA.into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            source_birth: digest(&owner.banks[0]),
            kernel_binding: digest(&owner.banks[1]),
            policy_binding: digest(&owner.banks[2]),
            host_registration: digest(&owner.host_body),
            native_registration: digest(&owner.banks[3]),
            hello_request: Bytes::new(pair.request_frame_digest.to_vec()),
            hello_response: Bytes::new(pair.response_frame_digest.to_vec()),
            assigned_restore: Bytes::new(
                complete_restore_transfer_assigned_request_digest(
                    original,
                    PacketCompleteRestoreTransferPhase::Commit,
                    maximum,
                )?
                .to_vec(),
            ),
            archive_binding: bindings.archive_binding,
            target_binding: bindings.target_binding,
            mapping_binding: bindings.mapping_binding,
            request_binding: bindings.request_binding,
        };
        flight.context = Some(PacketCompleteRestoreCommitContext {
            schema: "source-owned.packet-complete-restore-commit-context/12".into(),
            algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
            restoration: context,
            commit_request: digest(&bounded_canonical(
                request,
                MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
            )?),
            prepare_request: Bytes::new(request.prepare_request_digest.as_slice().to_vec()),
            prepare_response: Bytes::new(request.prepare_response_digest.as_slice().to_vec()),
            transfer_token: Bytes::new(request.transfer_token.as_slice().to_vec()),
            input_roster: request.prepare.input_roster_digest_data()?,
        });
        let request = flight.request.as_ref().ok_or_else(refused)?;
        let context = flight.context.as_ref().ok_or_else(refused)?;
        context.authenticate_request_data(request, mapping_data.normalization_bytes())?;
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        verify_complete_restore_commit_proof_data(
            key,
            context,
            flight.proof.as_ref().ok_or_else(refused)?,
        )?;
        drop(mapping_data);
        drop(flight);
        drop(owner);

        // The exact full input banks are verified by the SDK before this loan.
        // The called projector preflights all declared DOM/model/canonical work
        // before constructing any owned projection or model-adoption vectors.
        {
            let inputs = connection.original_complete_restore_input_state()?;
            let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
            let request = flight.request.as_ref().ok_or_else(refused)?;
            let input = PacketCompleteRestoreOwnerStateData {
                request,
                owner_state_bytes: inputs.original_input(3)?,
                journal_bytes: inputs.original_input(4)?,
                control_bytes: inputs.original_input(1)?,
                anchor_bytes: inputs.original_input(2)?,
            };
            if Self::original_restored_suffix_owner_present_data(boot)? {
                let launch = flight.launch.as_ref().ok_or_else(refused)?;
                let suffix_inputs = PacketCompleteRestoreSelectedOwnerInputs {
                    owner_state: input.owner_state_bytes,
                    journal: input.journal_bytes,
                    control: input.control_bytes,
                    anchor: input.anchor_bytes,
                    maximum_input_bytes: usize::try_from(
                        request.prepare.allocation.maximum_input_bytes.get(),
                    )
                    .map_err(|_| refused())?,
                    maximum_before_bytes: usize::try_from(
                        launch
                            .capture_profile
                            .native_before_bytes(&launch.storage)
                            .get(),
                    )
                    .map_err(|_| refused())?,
                    maximum_requested_bytes: usize::try_from(
                        request.prepare.allocation.maximum_model_bytes.get(),
                    )
                    .map_err(|_| refused())?,
                };
                Self::seal_original_restored_suffix_model_data(boot, launch, &suffix_inputs)?;
            }
            let selected = connection.original_complete_restore_selected_native_class_data()?;
            let owner_requested = match selected {
                Some(class) => crate::reference_packet::service::complete_restore::transfer::selected_owner_validation_storage_data(&input, class)?.total_bytes,
                None => complete_restore_owner_validation_storage_data(&input)?.total_bytes,
            };
            let maximum = usize::try_from(request.prepare.allocation.maximum_model_bytes.get())
                .map_err(|_| refused())?;
            let requested = flight
                .requested_model_bytes
                .checked_add(owner_requested)
                .filter(|requested| *requested <= maximum)
                .ok_or_else(refused)?;
            let projection = match selected {
                Some(class) => crate::reference_packet::service::complete_restore::transfer::authenticate_selected_owner_state_data(input, class)?,
                None => authenticate_complete_restore_owner_state_data(input)?,
            };
            flight.requested_model_bytes = requested;
            let (capture_request, pending_control) = projection.into_data_parts();
            flight.capture_request = Some(capture_request);
            flight.pending_control = Some(pending_control);
        }
        {
            let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
            let maximum = usize::try_from(
                flight
                    .request
                    .as_ref()
                    .ok_or_else(refused)?
                    .prepare
                    .allocation
                    .maximum_model_bytes
                    .get(),
            )
            .map_err(|_| refused())?
            .min(
                crate::reference_packet::control::packet_control_snapshot_validation_layouts()
                    .maximum_model_bytes,
            );
            let NativeCompleteRestoreAttempt {
                pending_control,
                prepared_model,
                ..
            } = &mut *flight;
            control.prepare_original_complete_model_into(
                pending_control,
                prepared_model,
                maximum,
            )?;
        }
        prepare_gate_evidence(&attempt)?;
        admission.authenticate_current(connection)?;
        let identity = connection.retain_original_native_restore_identity(original, policy)?;
        identity.authenticate_installation(connection, original)?;
        attempt.try_borrow_mut().map_err(|_| borrowed())?.verified = true;
        *completed = Some(VerifiedCompleteRestoration {
            identity,
            boot: Rc::clone(boot),
            policy: Rc::clone(policy),
            authority: authority.clone(),
            attempt,
        });
        Ok(())
    }

    pub(crate) fn install_complete_restore_model_into(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<crate::client::DeadlineStream>,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
        control: &mut PacketControl,
        held: &mut Option<VerifiedCompleteRestorationHeld>,
    ) -> Result<(), ProviderError> {
        connection.authenticate_installed_complete_restoration(mapping)?;
        let admission = connection.original_native_owned11_admission()?;
        if held.is_some() || !Rc::ptr_eq(boot, &admission.boot) {
            return Err(refused());
        }
        let attempt = {
            let owner = boot.try_borrow().map_err(|_| borrowed())?;
            owner.ensure_origin()?;
            Rc::clone(owner.restoration.as_ref().ok_or_else(refused)?)
        };
        let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified
            || !flight.installation_started
            || flight.physical_hold.is_some()
            || !Rc::ptr_eq(&flight.mapping, mapping)
        {
            return Err(refused());
        }
        let requirement = {
            let owner = boot.try_borrow().map_err(|_| borrowed())?;
            restoration_activation::original_restoration_activation_model_requirement_data(
                &owner, &flight,
            )?
        };
        let physical_hold = control.install_original_complete_model_with_activation_requirement(
            flight.prepared_model.as_mut().ok_or_else(refused)?,
            requirement,
        )?;
        flight.physical_hold = Some(Rc::clone(&physical_hold));
        drop(flight);
        *held = Some(VerifiedCompleteRestorationHeld {
            boot: Rc::clone(boot),
            mapping: Rc::clone(mapping),
            attempt,
            hold: physical_hold,
        });
        Ok(())
    }
}

impl VerifiedCompleteRestoration {
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
            || boot
                .policy
                .as_ref()
                .is_none_or(|policy| !Rc::ptr_eq(policy, &self.policy))
            || boot
                .restoration
                .as_ref()
                .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
            || !flight.verified
            || flight.original.is_none()
            || flight.request.is_none()
            || flight.proof.is_none()
            || flight.context.is_none()
            || flight.capture_request.is_none()
            || flight.prepared_model.is_none()
        {
            return Err(refused());
        }
        let mapping = flight.mapping.try_borrow().map_err(|_| borrowed())?;
        connection.authenticate_archived_native_protocol_mapping(&mapping)
    }

    pub(crate) fn authenticate_installation<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        if flight.installation_started || !Rc::ptr_eq(mapping, &flight.mapping) {
            return Err(refused());
        }
        self.identity
            .authenticate_installation(connection, flight.original.as_ref().ok_or_else(refused)?)
    }

    /// Loans the exact prebuilt future proof without granting an installed hold.
    pub(crate) fn original_prepared_gate_evidence<'a, S: ProviderStream>(
        &'a self,
        connection: &Connection<S>,
    ) -> Result<std::cell::Ref<'a, (ContentRef, Vec<u8>)>, ProviderError> {
        self.authenticate_current(connection)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        if flight.installation_started {
            return Err(refused());
        }
        std::cell::Ref::filter_map(flight, |flight| flight.gate_evidence.as_ref())
            .map_err(|_| refused())
    }

    pub(crate) fn begin_installation<S: ProviderStream>(
        &mut self,
        connection: &Connection<S>,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
    ) -> Result<(), ProviderError> {
        self.authenticate_installation(connection, mapping)?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        if flight.installation_started {
            return Err(refused());
        }
        flight.installation_started = true;
        Ok(())
    }
}

impl NativeCompleteRestoreAttempt {
    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

fn authenticate_host_projection(
    projection: &serde_json::Value,
    expected: &serde_json::Value,
) -> Result<(), ProviderError> {
    let fields = projection.as_array().ok_or_else(refused)?;
    if fields.len() != 10
        || fields[0] != "source-private.connection-authority/11"
        || fields[9] != "original-registration-backing-retained-by-opaque-source"
    {
        return Err(refused());
    }
    U64::deserialize(&fields[4]).map_err(ContractError::from)?;
    for (index, key) in [
        (1, "connection_id"),
        (2, "session_id"),
        (3, "incarnation_id"),
        (5, "limits"),
        (6, "features"),
        (7, "envelope_extensions"),
        (8, "extensions"),
    ] {
        if fields[index] != expected[key] {
            return Err(refused());
        }
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> Bytes {
    Bytes::new(blake3::hash(bytes).as_bytes().to_vec())
}
fn refused() -> ProviderError {
    ProviderError::Correlation("fresh original two-phase complete restoration differs")
}
fn borrowed() -> ProviderError {
    ProviderError::Conflict("fresh original two-phase complete restoration borrowed")
}

// The negotiated incoming DOM already exists in the SDK. This nonallocating
// walk charges a retained Envelope clone and typed Commit projections using the
// actual private maximum slot layout, plus a separately scanned original launch.
fn quoted_commit_decode_storage(
    original: &Envelope,
    owner: &NativeAckBoot,
    maximum: usize,
) -> Result<usize, ProviderError> {
    use crate::retained_metadata::MetadataObserver;
    let mut observer = MetadataObserver::new();
    observer.observe(original)?;
    observer.observe(&owner.data.source_birth)?;
    observer.observe(&owner.data.expected_host_registration)?;
    observer.observe(&owner.normalized[1])?;
    observer.observe(&owner.normalized[2])?;
    let facts = observer.finish();
    let layouts = crate::reference_packet::control::packet_control_snapshot_validation_layouts();
    let slot = layouts
        .maximum_typed_slot_bytes
        .max(std::mem::size_of::<PacketCompleteRestoreCommitRequest>())
        .max(std::mem::size_of::<PacketNative5SourceLaunch>());
    let retained = super::restore_prepare::known_backing_bytes(facts)?;
    let typed = facts.observed_nodes.checked_mul(slot).ok_or_else(refused)?;
    let launch = selected_issuer_decode_storage_data(
        owner.original_verified_launch_literal_data()?,
        slot,
        maximum,
    )?;
    let headers = std::mem::size_of::<NativeCompleteRestoreAttempt>()
        .checked_add(std::mem::size_of::<PacketPreparedCompleteModel>())
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<PacketCompleteRestorePhysicalHold>())
        })
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<VerifiedCompleteRestoration>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<VerifiedCompleteRestorationHeld>()))
        .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<usize>()))
        .ok_or_else(refused)?;
    let proof = maximum_complete_restore_held_evidence_bytes()?;
    let total = [
        retained,
        typed,
        launch,
        headers,
        proof,
        proof,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        65_536,
    ]
    .into_iter()
    .try_fold(0usize, |total, bytes| {
        total.checked_add(bytes).ok_or_else(refused)
    })?;
    if total > maximum {
        return Err(refused());
    }
    Ok(total)
}

#[path = "restore/settled_current.rs"]
mod settled_current;

#[path = "restore/settled_token.rs"]
mod settled_token_history;
