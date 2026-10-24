//! Verifies separately funded Arm and WorldActivate against the same restored boot.
//!
//! Each slot is consumed before parsing. Original requests, typed partials and
//! publication state stay under the original boot after any refusal or unwind.
//! The short-lived permit is private to this actual native verification path;
//! decoded phase labels, allocation rows and valid syntax cannot construct it.

use super::*;
use crate::reference_packet::service::complete_restore::activation::*;
use crate::retained_metadata::MetadataObserver;
use std::mem::size_of;

#[path = "restoration_activation/observation.rs"]
mod observation;
#[path = "restoration_activation/released.rs"]
mod released;
#[path = "restoration_activation/upload.rs"]
mod upload;
pub(crate) use observation::{
    NativeRestorationObservationAttempt, OriginalRestorationObservationPermit,
    OriginalRestorationObservationRead, OriginalRestoredSuffixPostObservation,
    original_native_restoration_observation_attempt_backing_data,
    original_native_restoration_observation_counter_scratch_data,
    original_native_restoration_observation_ingress_row_data,
    original_restored_suffix_post_observation_counter_scratch_data,
};
pub(crate) use released::{OriginalRestorationReleaseState, OriginalRestorationReleased};
pub(crate) use upload::{
    NativeRestorationUploadAttempt, OriginalRestorationUploadPermit,
    original_native_restoration_upload_attempt_backing_data,
    original_native_restoration_upload_counter_scratch_data,
};

pub(crate) struct NativeRestorationActivationAttempt {
    creator: u32,
    thread: ThreadId,
    phase: PacketRestorationActivationPhase,
    original: Option<Envelope>,
    incoming_slot: Option<usize>,
    artifact: Option<PacketRestorationActivationArtifact>,
    context: Option<PacketRestorationActivationContext>,
    coordinator: Option<serde_json::Value>,
    manifest: Option<crucible_node_format::ActivationManifest>,
    terminal: Option<Envelope>,
    verified: bool,
    dispatched: bool,
    published: bool,
}

/// Carries one verified original into the same native Control dispatcher.
///
/// This token is neither cloneable nor independently constructible. Its attempt
/// has no strong boot edge: the boot owns both once slots without an Rc cycle.
pub(crate) struct OriginalRestorationActivationPermit {
    boot: Rc<RefCell<NativeAckBoot>>,
    attempt: Rc<RefCell<NativeRestorationActivationAttempt>>,
    commit: Rc<RefCell<NativeCompleteRestoreAttempt>>,
    hold: Rc<PacketCompleteRestorePhysicalHold>,
    authority: ConnectionAuthority,
    policy: Rc<crate::reference_packet::Native5Policy>,
}

impl NativeAckBoot {
    /// Selects this new route from a genuine private target and installed feature.
    ///
    /// # Errors
    /// Refuses changed private provenance or an incomplete target baseline.
    pub(crate) fn requires_restoration_activation_data(&self) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        if !self.requires_invocation_codec_data()? {
            return Ok(false);
        }
        self.authenticate_original_invocation_baseline_data()?;
        if self.permits_original_invocation_without_fresh_query_data()? {
            return Ok(false);
        }
        let policy = self.policy.as_ref().ok_or_else(refused)?;
        Ok(policy
            .original_restoration_activation_selection_data()
            .provider
            .extensions_supported
            .iter()
            .any(|id| id.as_str() == PACKET_RESTORATION_ACTIVATION_FEATURE))
    }

    /// Retains and authenticates one actual native activation request.
    ///
    /// The already admitted fixed ingress covers slot/header creation and the
    /// bounded artifact/MAC work. The signed phase row is independently counted
    /// before any additional model, coordinator DOM or publication construction.
    ///
    /// # Errors
    /// Refuses replay, foreign origin, changed Commit/target/private purpose,
    /// invalid full-request MAC or an insufficient independently signed axis.
    pub(crate) fn retain_restoration_activation<S: ProviderStream>(
        boot: &Rc<RefCell<Self>>,
        connection: &Connection<S>,
        original: Envelope,
        control: &PacketControl,
    ) -> Result<OriginalRestorationActivationPermit, ProviderError> {
        let phase = match original.method {
            crate::envelope::Method::Activate => PacketRestorationActivationPhase::Arm,
            crate::envelope::Method::WorldActivate => {
                PacketRestorationActivationPhase::WorldActivate
            }
            _ => return Err(refused()),
        };
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        if !Rc::ptr_eq(boot, &admission.boot) {
            return Err(refused());
        }

        let attempt = {
            let mut owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
            owner.ensure_origin()?;
            if !owner.requires_restoration_activation_data()? {
                return Err(refused());
            }
            owner
                .startup
                .as_ref()
                .ok_or_else(refused)?
                .allocation
                .native_birth
                .authenticate_actual_data(
                    &original_native_restoration_activation_ingress_row_data(
                        usize::try_from(admission.authority.limits().frame_bytes.get())
                            .map_err(|_| refused())?,
                    )?,
                )?;
            let slot = &mut owner.restoration_activation[phase_index(phase)];
            if slot.is_some() {
                return Err(ProviderError::Conflict(
                    "native restoration activation already attempted",
                ));
            }
            let attempt = Rc::new(RefCell::new(NativeRestorationActivationAttempt {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                phase,
                original: Some(original),
                incoming_slot: None,
                artifact: None,
                context: None,
                coordinator: None,
                manifest: None,
                terminal: None,
                verified: false,
                dispatched: false,
                published: false,
            }));
            *slot = Some(Rc::clone(&attempt));
            attempt
        };

        // Retain the actual reader slot after the once original is owned and
        // before its artifact is parsed. Future release/Observe checks borrow
        // these exact physical canonical bytes without constructing a clone.
        if phase == PacketRestorationActivationPhase::WorldActivate
            && admission.policy.original_restoration_activation_selection_data()
                .provider.extensions_supported.iter().any(|feature| feature.as_str() ==
                    crate::reference_packet::service::complete_restore::restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE)
        {
            let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
            let slot = connection.original_restoration_incoming_literal_slot_data(
                flight.original.as_ref().ok_or_else(refused)?,
            )?;
            flight.incoming_slot = Some(slot);
        }

        // Parse directly from the original already moved into the sticky slot.
        // Assign each complete typed partial before its subsequent validation.
        {
            let artifact = {
                let flight = attempt.try_borrow().map_err(|_| borrowed())?;
                let original = flight.original.as_ref().ok_or_else(refused)?;
                let value = original
                    .extensions
                    .get(PACKET_RESTORATION_ACTIVATION_FEATURE)
                    .ok_or_else(refused)?;
                crate::connection::serialized_credit(
                    value,
                    MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
                )?;
                PacketRestorationActivationArtifact::deserialize(value)
                    .map_err(ContractError::from)?
            };
            attempt.try_borrow_mut().map_err(|_| borrowed())?.artifact = Some(artifact);
        }

        let owner = boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let commit = Rc::clone(owner.restoration.as_ref().ok_or_else(refused)?);
        let restored = commit.try_borrow().map_err(|_| borrowed())?;
        restored.ensure_origin()?;
        if !restored.verified
            || !restored.installation_started
            || !restored.receipt_started
            || restored.receipt_body.is_empty()
            || restored.response_body.is_empty()
        {
            return Err(refused());
        }
        let hold = Rc::clone(restored.physical_hold.as_ref().ok_or_else(refused)?);
        hold.authenticate_held()?;
        control.authenticate_original_restoration_activation_hold_data(&hold)?;
        connection.authenticate_installed_complete_restoration(&restored.mapping)?;
        let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
        artifact.validate_data()?;
        if artifact.request.phase != phase {
            return Err(refused());
        }
        let scope = &artifact.request.scope;
        let purpose = owner.authenticate_original_invocation_birth_data()?;
        purpose.authenticate_restoration_source_data(
            &scope.source_runtime,
            &scope.restoration.captured_owner_state,
            &scope.target.owner,
        )?;
        authenticate_completed_commit(&owner, &restored, scope)?;
        authenticate_phase_original(
            flight.original.as_ref().ok_or_else(refused)?,
            &artifact.request,
            &admission.authority,
            &admission.policy,
        )?;
        if phase == PacketRestorationActivationPhase::WorldActivate {
            let arm = owner.restoration_activation[0]
                .as_ref()
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| borrowed())?;
            arm.ensure_origin()?;
            if !arm.published
                || !arm.dispatched
                || !arm.verified
                || arm.artifact.as_ref().ok_or_else(refused)?.request.scope != *scope
            {
                return Err(refused());
            }
        }
        if phase == PacketRestorationActivationPhase::WorldActivate {
            owner.authenticate_restoration_activation_uploads_data(
                scope,
                flight.original.as_ref().ok_or_else(refused)?,
            )?;
        }
        let assigned = restoration_activation_assigned_request_digest(
            flight.original.as_ref().ok_or_else(refused)?,
            phase,
            usize::try_from(admission.authority.limits().frame_bytes.get())
                .map_err(|_| refused())?,
        )?;
        let context = PacketRestorationActivationContext {
            request: artifact.request.clone(),
            assigned_request: Bytes::new(assigned.to_vec()),
        };
        flight.context = Some(context);
        let artifact = flight.artifact.as_ref().ok_or_else(refused)?;
        let key: &[u8; 32] = owner
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        verify_restoration_activation_proof_data(
            key,
            flight.context.as_ref().ok_or_else(refused)?,
            &artifact.proof,
        )?;

        // These are the same retained native six-input custody banks used by
        // Commit, not reconstructed Source DTOs or archived encoded-length hints.
        let inputs = connection.original_complete_restore_input_state()?;
        let request = restored.request.as_ref().ok_or_else(refused)?;
        let maximum = usize::try_from(
            flight
                .artifact
                .as_ref()
                .ok_or_else(refused)?
                .request
                .native_allocation
                .requested_bytes_data()?,
        )
        .map_err(|_| refused())?;
        let launch = restored.launch.as_ref().ok_or_else(refused)?;
        let selected = PacketCompleteRestoreSelectedOwnerInputs {
            owner_state: inputs.original_input(3)?,
            journal: inputs.original_input(4)?,
            control: inputs.original_input(1)?,
            anchor: inputs.original_input(2)?,
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
            maximum_requested_bytes: maximum,
        };
        let available = artifact.request.native_allocation;
        let NativeRestorationActivationAttempt {
            original, manifest, ..
        } = &mut *flight;
        let coordinator = control.original_restoration_activation_coordinator_data(
            original.as_ref().ok_or_else(refused)?,
            phase,
            manifest,
        )?;
        if let Some(manifest) = flight.manifest.as_ref() {
            owner.authenticate_restoration_uploaded_coordinator_data(
                &flight.artifact.as_ref().ok_or_else(refused)?.request.scope,
                &manifest.coordinator_state_ref,
            )?;
        }
        let required = original_native_restoration_activation_required_storage_data(
            launch,
            &selected,
            phase,
            coordinator,
        )?;
        authenticate_row(&available, &required)?;
        if let Some(raw) = coordinator {
            flight.coordinator = Some(canonical::parse_json(raw, raw.len())?);
        }
        flight.verified = true;
        drop(flight);
        drop(restored);
        drop(owner);
        admission.authenticate_current(connection)?;
        Ok(OriginalRestorationActivationPermit {
            boot: Rc::clone(boot),
            attempt,
            commit,
            hold,
            authority: admission.authority.clone(),
            policy: Rc::clone(&admission.policy),
        })
    }
}

fn authenticate_completed_commit(
    owner: &NativeAckBoot,
    flight: &NativeCompleteRestoreAttempt,
    scope: &PacketRestorationActivationScope,
) -> Result<(), ProviderError> {
    let request = flight.request.as_ref().ok_or_else(refused)?;
    let target = &request.prepare.restoration;
    let gate = flight.gate_data.as_ref().ok_or_else(refused)?;
    gate.validate_data()?;
    let expected_birth = canonical::content_ref(&owner.banks[0], "application/json")?;
    if scope.source_birth != expected_birth
        || scope.source_runtime != target.source_runtime
        || scope.target.native_pid.get() != u64::from(std::process::id())
        || scope.target.owner != target.target_owner
        || scope.target.owner_generation != target.target_owner_generation
        || scope.target.binding_hash != target.target_owner_binding
        || scope.target.world != target.target_world
        || scope.target.activation != target.target_activation
        || scope.target.generation != target.target_generation
        || scope.restoration.captured_owner_state != target.owner_state
        || scope.restoration.captured_control != request.prepare.native_control
        || scope.restoration.captured_journal != target.journal
        || scope.restoration.mapping != target.mapping
        || scope.restoration.commit_request != gate.restore_commit
        || Some(&scope.restoration.commit_response) != flight.completed_response.as_ref()
        || scope.restoration.context_digest != gate.context_digest
    {
        return Err(refused());
    }
    Ok(())
}

fn authenticate_phase_original(
    original: &Envelope,
    request: &PacketRestorationActivationRequest,
    authority: &ConnectionAuthority,
    policy: &crate::reference_packet::Native5Policy,
) -> Result<(), ProviderError> {
    use crate::bodies::RequestBody;
    use crate::bodies::decode_request;
    use crate::envelope::MessageKind;
    authenticate_restoration_activation_selection_data(
        policy.original_restoration_activation_selection_data(),
        authority,
    )?;
    if original.message != MessageKind::Request
        || original.method != request.phase.method()
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
    let command = match decode_request(original.method, &original.body)? {
        RequestBody::Activate(body) => PacketRestorationActivationCommand::Arm(body),
        RequestBody::WorldActivate(body) => PacketRestorationActivationCommand::WorldActivate(body),
        _ => return Err(refused()),
    };
    command.authenticate_request_data(request)?;
    let selection = policy.original_restoration_activation_selection_data();
    let binding = selection.realization.bindings.first().ok_or_else(refused)?;
    if request.scope.target.prepared_token != selection.prepared_token
        || request.scope.target.admission != selection.admission
        || request.scope.target.transaction != selection.transaction
        || request.scope.target.gate != selection.gate
        || request.scope.target.world != selection.world
        || request.scope.target.node != binding.compatibility.node_id
        || request.scope.target.session != *authority.session_id()
        || request.scope.target.incarnation != *authority.incarnation_id()
    {
        return Err(refused());
    }
    authority.ensure_live()
}

fn authenticate_row(
    available: &PacketRestorationActivationAllocationRow,
    required: &PacketRestorationActivationAllocationRow,
) -> Result<(), ProviderError> {
    available.requested_bytes_data()?;
    required.requested_bytes_data()?;
    if available.retained_requested_bytes < required.retained_requested_bytes
        || available.maximum_simultaneous_transient_bytes
            < required.maximum_simultaneous_transient_bytes
        || available.declared_counter_scratch_bytes < required.declared_counter_scratch_bytes
    {
        return Err(ProviderError::ResourceExhausted(
            "native restoration activation phase row",
        ));
    }
    Ok(())
}

const fn phase_index(phase: PacketRestorationActivationPhase) -> usize {
    match phase {
        PacketRestorationActivationPhase::Arm => 0,
        PacketRestorationActivationPhase::WorldActivate => 1,
    }
}

impl NativeRestorationActivationAttempt {
    fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        Ok(())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original native restoration activation differs")
}

fn borrowed() -> ProviderError {
    ProviderError::Conflict("original native restoration activation borrowed")
}

/// Names native activation's actual fixed owner, borrowing and conversion views.
pub(crate) fn original_native_restoration_activation_counter_scratch_data() -> usize {
    crate::connection::original_restored_response_counter_scratch_data()
        + size_of::<NativeRestorationActivationAttempt>()
        + size_of::<PacketRestorationActivationArtifact>() * 2
        + size_of::<PacketRestorationActivationContext>() * 2
        + size_of::<Result<PacketRestorationActivationArtifact, serde_json::Error>>()
        + size_of::<Result<PacketRestorationActivationContext, ProviderError>>()
        + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeAckBoot>, std::cell::BorrowMutError>>()
        + size_of::<Result<std::cell::Ref<'static, NativeCompleteRestoreAttempt>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::Ref<'static, NativeRestorationActivationAttempt>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeRestorationActivationAttempt>, std::cell::BorrowMutError>>()
        + size_of::<Result<std::cell::Ref<'static, serde_json::Value>, ProviderError>>()
        + size_of::<Result<std::cell::Ref<'static, Envelope>, std::cell::Ref<'static, NativeRestorationActivationAttempt>>>()
        + size_of::<Result<std::cell::Ref<'static, PacketRestorationActivationArtifact>, std::cell::Ref<'static, NativeRestorationActivationAttempt>>>()
        + size_of::<Result<std::cell::Ref<'static, serde_json::Value>, std::cell::Ref<'static, NativeRestorationActivationAttempt>>>()
        + size_of::<OriginalRestorationActivationPermit>()
        + size_of::<OriginalRestorationActivationRequirement>()
        + size_of::<Result<OriginalRestorationActivationRequirement, ProviderError>>()
        + size_of::<crate::retained_metadata::MetadataObserver<'static>>()
        + size_of::<crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData>() * 3
        + size_of::<crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow>()
        + size_of::<Result<crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<[usize; 12]>()
        + size_of::<std::array::IntoIter<usize, 2>>()
        + size_of::<std::slice::Iter<'static, Option<Rc<RefCell<NativeRestorationActivationAttempt>>>>>()
        + crate::retained_metadata::serialization_storage::original_json_value_storage_extent_counter_scratch_data()
        + crate::reference_packet::control::original_restoration_coordinator_counter_scratch_data()
        + size_of::<[Option<Rc<RefCell<NativeRestorationActivationAttempt>>>; 2]>()
        + size_of::<std::cell::Ref<'static, NativeAckBoot>>()
        + size_of::<std::cell::RefMut<'static, NativeAckBoot>>()
        + size_of::<std::cell::Ref<'static, NativeCompleteRestoreAttempt>>()
        + size_of::<std::cell::Ref<'static, NativeRestorationActivationAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestorationActivationAttempt>>()
        + size_of::<Result<std::cell::Ref<'static, Envelope>, ProviderError>>()
        + size_of::<Result<std::cell::Ref<'static, PacketRestorationActivationArtifact>, ProviderError>>()
        + size_of::<Result<OriginalRestorationActivationPermit, ProviderError>>()
        + size_of::<Result<Option<&'static [u8]>, ProviderError>>()
        + size_of::<Result<PacketRestorationActivationAllocationRow, ProviderError>>()
        + size_of::<Option<crucible_node_format::ActivationManifest>>()
        + size_of::<Result<crucible_node_format::ActivationManifest, ContractError>>()
        + size_of::<PacketCompleteRestoreSelectedOwnerInputs<'static>>()
        + size_of::<Result<serde_json::Value, ContractError>>()
        + size_of::<Option<&'static [u8]>>()
        + size_of::<Result<ContentRef, ContractError>>()
        + size_of::<[u8; 32]>()
        + size_of::<Result<&'static [u8; 32], std::array::TryFromSliceError>>()
        + size_of::<std::array::IntoIter<usize, 2>>()
        + restoration_activation_protocol_counter_scratch_data()
        + original_native_restoration_upload_counter_scratch_data()
        + released::counter_scratch_data()
}

/// Quotes fixed ingress before any untrusted artifact can supply a phase row.
///
/// This is an additional pre-Child obligation, independent of private Commit
/// credit. It bounds all raw occurrences, complete canonical work and typed
/// prefix allocations under the actual artifact and manifest hard ceilings.
/// Recursive/compiler frames and allocator physical overhead remain separate.
pub(crate) fn original_native_restoration_activation_ingress_storage_data()
-> Result<usize, ProviderError> {
    use crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data;
    let mut total = original_native_restoration_activation_counter_scratch_data();
    for maximum in [MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES, 65_536] {
        let raw = original_json_value_storage_extent_data(maximum)?;
        // The artifact/context DTOs have fixed nested fields; only the manifest
        // has growable PreparedOwner/HashRef/ContentRef/string element vectors.
        let element = size_of::<crucible_node_format::PreparedOwner>()
            .max(size_of::<ContentRef>())
            .max(size_of::<crucible_node_format::HashRef>())
            .max(size_of::<String>());
        let typed = raw
            .maximum_value_nodes
            .checked_mul(4)
            .and_then(|count| count.checked_mul(element))
            .ok_or_else(refused)?;
        let phase = raw
            .canonical_pass_requested_bytes()?
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(typed))
            .and_then(|bytes| bytes.checked_add(maximum))
            .ok_or_else(refused)?;
        total = total.checked_add(phase).ok_or_else(refused)?;
    }
    Ok(total)
}

impl OriginalRestorationActivationPermit {
    pub(crate) fn original_data(&self) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        std::cell::Ref::filter_map(flight, |flight| flight.original.as_ref()).map_err(|_| refused())
    }

    pub(crate) fn artifact_data(
        &self,
    ) -> Result<std::cell::Ref<'_, PacketRestorationActivationArtifact>, ProviderError> {
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        std::cell::Ref::filter_map(flight, |flight| flight.artifact.as_ref()).map_err(|_| refused())
    }

    pub(crate) fn coordinator_data(
        &self,
    ) -> Result<std::cell::Ref<'_, serde_json::Value>, ProviderError> {
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        std::cell::Ref::filter_map(flight, |flight| flight.coordinator.as_ref())
            .map_err(|_| refused())
    }

    pub(crate) fn authenticate_control_request(
        &self,
        original: &Envelope,
        selection: &crate::reference_packet::control::PacketControlSelection,
        actual_hold: &Rc<PacketCompleteRestorePhysicalHold>,
    ) -> Result<(), ProviderError> {
        self.authority.ensure_live()?;
        self.policy
            .authenticate_original_control_selection(selection)?;
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        let commit = self.commit.try_borrow().map_err(|_| borrowed())?;
        commit.ensure_origin()?;
        if !flight.verified
            || !flight.dispatched
            || flight.published
            || !std::ptr::eq(original, flight.original.as_ref().ok_or_else(refused)?)
            || owner.restoration_activation[phase_index(flight.phase)]
                .as_ref()
                .is_none_or(|slot| !Rc::ptr_eq(slot, &self.attempt))
            || owner
                .restoration
                .as_ref()
                .is_none_or(|slot| !Rc::ptr_eq(slot, &self.commit))
            || commit
                .physical_hold
                .as_ref()
                .is_none_or(|hold| !Rc::ptr_eq(hold, &self.hold))
            || !Rc::ptr_eq(actual_hold, &self.hold)
            || owner
                .policy
                .as_ref()
                .is_none_or(|policy| !Rc::ptr_eq(policy, &self.policy))
        {
            return Err(refused());
        }
        self.hold.authenticate_held()
    }

    pub(crate) fn begin_dispatch_data(&self) -> Result<(), ProviderError> {
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified || flight.dispatched || flight.published {
            return Err(refused());
        }
        flight.dispatched = true;
        Ok(())
    }

    /// Marks only the actually completed same-connection proof publication.
    ///
    /// # Errors
    /// Refuses a changed actor/boot, unsent suffix, wrong terminal correlation or
    /// disagreement between the actual phase and current physical hold.
    pub(crate) fn complete_publication<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        record: &crate::connection::ExchangeRecord,
    ) -> Result<(), ProviderError> {
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        connection.authenticate_installed_complete_restoration(
            &self.commit.try_borrow().map_err(|_| borrowed())?.mapping,
        )?;
        if !Rc::ptr_eq(&admission.boot, &self.boot)
            || !Rc::ptr_eq(&admission.policy, &self.policy)
            || record.sent() != record.originals().len()
        {
            return Err(refused());
        }
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if !flight.verified || !flight.dispatched || flight.published {
            return Err(refused());
        }
        let (terminal_index, terminal) = {
            let original = flight.original.as_ref().ok_or_else(refused)?;
            crate::connection::original_restored_response_data(original, record.originals())?
        };
        // The actual prefix owns every response even if lookup refuses. Once
        // selected, also retain this terminal before typed/held validation.
        flight.terminal = Some(terminal.clone());
        let original = flight.original.as_ref().ok_or_else(refused)?;
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
        let held = self.hold.physical_gate_data()?;
        if held != (flight.phase == PacketRestorationActivationPhase::Arm) {
            return Err(refused());
        }
        if record
            .original_sent_frame(connection, terminal_index)?
            .original()
            != terminal
        {
            return Err(refused());
        }
        for index in 0..record.originals().len() {
            record.original_sent_frame(connection, index)?;
        }
        flight.published = true;
        Ok(())
    }
}

impl NativeAckBoot {
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn observe_restoration_activation_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        for slot in &self.restoration_activation {
            if let Some(attempt) = slot {
                observer.shared_original(
                    crate::retained_metadata::aliases::MetadataSharedKind::NativeRestorationActivationAttempt,
                    attempt.as_ref(),
                )?;
                let flight = attempt.try_borrow().map_err(|_| borrowed())?;
                flight.ensure_origin()?;
                let NativeRestorationActivationAttempt {
                    creator,
                    thread: _,
                    phase,
                    original,
                    incoming_slot,
                    artifact,
                    context,
                    coordinator,
                    manifest,
                    terminal,
                    verified,
                    dispatched,
                    published,
                } = &*flight;
                observer.observe(creator)?;
                observer.observe(phase)?;
                observer.observe(original)?;
                observer.observe(incoming_slot)?;
                if let Some(artifact) = artifact {
                    artifact.observe_owned_metadata_data(observer)?;
                }
                if let Some(context) = context {
                    context.observe_owned_metadata_data(observer)?;
                }
                observer.observe(coordinator)?;
                if let Some(manifest) = manifest {
                    observe_manifest(manifest, observer)?;
                }
                observer.observe(terminal)?;
                observer.observe(verified)?;
                observer.observe(dispatched)?;
                observer.observe(published)?;
            }
        }
        Ok(())
    }
}

fn observe_manifest(
    manifest: &crucible_node_format::ActivationManifest,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let crucible_node_format::ActivationManifest {
        schema_version,
        transaction_id,
        activation_id,
        world_generation,
        world_binding_hash,
        gate_id,
        owners,
        coordinator_state_ref,
        extensions,
    } = manifest;
    observer.observe(schema_version)?;
    observer.observe(transaction_id)?;
    observer.observe(activation_id)?;
    observer.observe(world_generation)?;
    observer.observe(world_binding_hash)?;
    observer.observe(gate_id)?;
    observer.vector::<crucible_node_format::PreparedOwner>(owners.capacity())?;
    for owner in owners {
        let crucible_node_format::PreparedOwner {
            owner_id,
            incarnation_id,
            owner_generation,
            binding_hashes,
            prepared_token,
            ready_receipt,
            extensions,
        } = owner;
        observer.observe(owner_id)?;
        observer.observe(incarnation_id)?;
        observer.observe(owner_generation)?;
        observer.observe(binding_hashes)?;
        observer.observe(prepared_token)?;
        observer.observe(ready_receipt)?;
        observer.observe(extensions)?;
    }
    observer.observe(coordinator_state_ref)?;
    observer.observe(extensions)
}

/// Quotes one actual Rc/RefCell attempt allocation, independently of scratch.
pub(crate) fn original_native_restoration_activation_attempt_backing_data()
-> Result<usize, ProviderError> {
    size_of::<RefCell<NativeRestorationActivationAttempt>>()
        .checked_add(
            crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                std::mem::align_of::<RefCell<NativeRestorationActivationAttempt>>(),
            )?,
        )
        .ok_or_else(refused)
}

/// Separates the genuine pre-Child ingress obligation into independent axes.
///
/// Four original requests and two independent unfinished upload requests can
/// remain live. Their full malformed-frame DOM bounds are
/// independent of an eventual valid signed row. Typed partials/context clones
/// and the bounded manifest owner remain funded on refusal as well as success.
pub(crate) fn original_native_restoration_activation_ingress_row_data(
    maximum_frame: usize,
) -> Result<
    crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow,
    ProviderError,
> {
    use crate::retained_metadata::serialization_storage::{
        original_json_value_storage_extent_data,
        original_serialization_tree_node_requested_bytes_data,
    };
    let frame = original_json_value_storage_extent_data(maximum_frame)?;
    let artifact =
        original_json_value_storage_extent_data(MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
    let logical_roots = frame
        .maximum_value_nodes
        .checked_mul(original_serialization_tree_node_requested_bytes_data::<
            String,
            serde_json::Value,
        >()?)
        .ok_or_else(refused)?;
    let once = frame
        .value_dom_requested_bytes
        .checked_add(logical_roots)
        .and_then(|bytes| bytes.checked_add(artifact.value_dom_requested_bytes.checked_mul(2)?))
        .and_then(|bytes| {
            bytes.checked_add(MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES.checked_mul(8)?)
        })
        .ok_or_else(refused)?;
    let manifest = frame
        .maximum_value_nodes
        .checked_mul(4)
        .and_then(|nodes| nodes.checked_mul(size_of::<crucible_node_format::PreparedOwner>()))
        .and_then(|bytes| bytes.checked_add(frame.value_dom_requested_bytes))
        .ok_or_else(refused)?;
    let activation_backing = original_native_restoration_activation_attempt_backing_data()?
        .checked_mul(2)
        .ok_or_else(refused)?;
    let upload_backing = original_native_restoration_upload_attempt_backing_data()?
        .checked_mul(2)
        .ok_or_else(refused)?;
    let typed_roots = size_of::<PacketRestorationActivationArtifact>()
        .checked_add(size_of::<PacketRestorationActivationContext>())
        .and_then(|bytes| bytes.checked_add(size_of::<crate::reference_packet::service::complete_restore::activation::upload::PacketRestorationActivationUploadArtifact>()))
        .and_then(|bytes| bytes.checked_add(size_of::<crate::reference_packet::service::complete_restore::activation::upload::PacketRestorationActivationUploadContext>()))
        .and_then(|bytes| bytes.checked_mul(2)).ok_or_else(refused)?;
    let retained = once
        .checked_mul(6)
        .and_then(|bytes| bytes.checked_add(typed_roots))
        .and_then(|bytes| bytes.checked_add(manifest))
        .and_then(|bytes| bytes.checked_add(activation_backing))
        .and_then(|bytes| bytes.checked_add(upload_backing))
        .ok_or_else(refused)?;
    let transient = original_native_restoration_activation_ingress_storage_data()?
        .checked_add(frame.canonical_pass_requested_bytes()?)
        .ok_or_else(refused)?;
    Ok(
        crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(u64::try_from(retained).map_err(|_| refused())?),
            maximum_simultaneous_transient_bytes: U64::new(
                u64::try_from(transient).map_err(|_| refused())?,
            ),
            declared_counter_scratch_bytes: U64::new(
                u64::try_from(original_native_restoration_activation_counter_scratch_data())
                    .map_err(|_| refused())?,
            ),
        },
    )
}

/// Selects the activation gate policy from the actual verified private boot.
///
/// This handoff can only tighten dispatch for its same prepared model and
/// immutable policy; it cannot issue an Arm or WorldActivate permission.
pub(crate) struct OriginalRestorationActivationRequirement {
    model: *const PacketPreparedCompleteModel,
    policy: Rc<crate::reference_packet::Native5Policy>,
    required: bool,
}

pub(super) fn original_restoration_activation_model_requirement_data(
    owner: &NativeAckBoot,
    flight: &NativeCompleteRestoreAttempt,
) -> Result<OriginalRestorationActivationRequirement, ProviderError> {
    owner.ensure_origin()?;
    flight.ensure_origin()?;
    if !flight.verified || !flight.installation_started || flight.physical_hold.is_some() {
        return Err(refused());
    }
    let model = flight.prepared_model.as_ref().ok_or_else(refused)?;
    Ok(OriginalRestorationActivationRequirement {
        model,
        policy: Rc::clone(owner.policy.as_ref().ok_or_else(refused)?),
        required: owner.requires_restoration_activation_data()?,
    })
}

impl OriginalRestorationActivationRequirement {
    pub(crate) fn authenticate_model_data(
        &self,
        model: &PacketPreparedCompleteModel,
        selection: &crate::reference_packet::control::PacketControlSelection,
    ) -> Result<bool, ProviderError> {
        if !std::ptr::eq(self.model, model) {
            return Err(refused());
        }
        self.policy
            .authenticate_original_control_selection(selection)?;
        Ok(self.required)
    }
}

#[cfg(test)]
#[path = "restoration_activation/tests.rs"]
mod tests;

#[path = "restoration_activation/settled.rs"]
mod settled;

pub(crate) use observation::{
    NativeObservation17OwningCheckpointData,
    original_observation17_checkpoint_owner_counter_scratch_data,
};
