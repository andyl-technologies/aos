//! Retains the actual startup16 reservation separately from every old boot lane.
//!
//! Its constructor requires the same authenticated inherited prefix and complete
//! Source15/boot7 correspondence. Cached archive geometry is unavailable at boot;
//! it is sealed later from the actual signed restoration input banks. Numeric
//! rows and this owner do not enable an Endpoint action or a Capture codec.

use super::*;
use crate::reference_packet::service::native_startup::*;
use crate::retained_metadata::MetadataObserver;
use std::mem::size_of;

/// Retains the independently received reservation, fixed ledger and actual links.
pub(in crate::reference_packet::service::ack_emitter::native_boot) struct NativeRestoredSuffixStartupOwner
{
    creator: u32,
    thread: ThreadId,
    preamble: [u8; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES],
    reservation: PacketRestoredSuffixReservationData,
    ledger: OriginalRestoredSuffixBudget,
    raw7: [u8; 32],
    raw7_bytes: usize,
    raw5: [u8; 32],
    raw5_bytes: usize,
    sealed: Option<PacketNativeRestoredSuffixStartupStorageData>,
    failed: bool,
    post_record: Option<usize>,
    observation: std::rc::Weak<RefCell<NativeRestorationObservationAttempt>>,
}

impl NativeRestoredSuffixStartupOwner {
    /// Checks the actual process/thread and sticky native failure state.
    ///
    /// # Errors
    /// Refuses inherited, foreign-thread or poisoned owners.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn ensure_current(
        &self,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || self.failed
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Copies the reservation only after the actual input geometry is sealed.
    ///
    /// # Errors
    /// Refuses a foreign, failed or not-yet-sealed native owner.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn reservation_data(
        &self,
    ) -> Result<PacketRestoredSuffixReservationData, ProviderError> {
        self.ensure_current()?;
        if self.sealed.is_none() {
            return Err(refused());
        }
        Ok(self.reservation)
    }

    /// Checks repeated initial-proof work against the independent new window.
    ///
    /// # Errors
    /// Refuses failed or unsealed state, another first-Observe domain or any short
    /// independently admitted axis. The request row remains demand DATA only.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_witness_storage_data(
        &self,
        actual: &crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest,
    ) -> Result<(), ProviderError> {
        self.ensure_current()?;
        if self.sealed.is_none() {
            return Err(refused());
        }
        // The actual signed first-Observe request supplies a demand, never a
        // startup grant. Its closed domain and every axis must fit the sealed,
        // independently admitted suffix window before repeated witness work.
        actual.validate_data()?;
        authenticate_initial_observation_projection_data(
            &self.reservation.actions,
            &actual.schema,
            actual.maximum_items,
            &actual.native_allocation,
        )
    }

    /// Poisons the private link before any fallible publication recheck.
    ///
    /// # Errors
    /// Refuses another attempt, foreign origin or absent actual geometry.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn begin_observation_publication_data(
        &mut self,
    ) -> Result<(), ProviderError> {
        self.ensure_current()?;
        if self.sealed.is_none()
            || self.post_record.is_some()
            || self.observation.upgrade().is_some()
        {
            return Err(refused());
        }
        self.failed = true;
        Ok(())
    }

    /// Closes the actual publication check with the same retained once attempt.
    ///
    /// # Errors
    /// Refuses foreign origin, absent pending work or a repeated publication.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn publish_observation_data(
        &mut self,
        attempt: &Rc<RefCell<NativeRestorationObservationAttempt>>,
        record: usize,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || !self.failed
            || self.sealed.is_none()
            || self.post_record.is_some()
            || self.observation.upgrade().is_some()
        {
            return Err(refused());
        }
        self.post_record = Some(record);
        self.observation = Rc::downgrade(attempt);
        self.failed = false;
        Ok(())
    }

    /// Compares the same retained attempt and exact published record ordinal.
    ///
    /// # Errors
    /// Refuses failed state, absent geometry or a foreign attempt/record.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_observation_data(
        &self,
        attempt: &Rc<RefCell<NativeRestorationObservationAttempt>>,
        record: usize,
    ) -> Result<(), ProviderError> {
        self.ensure_current()?;
        if self.sealed.is_none()
            || self.post_record != Some(record)
            || self
                .observation
                .upgrade()
                .is_none_or(|saved| !Rc::ptr_eq(&saved, attempt))
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Counts the fixed Box even when a failed attempt remains owned.
    ///
    /// # Errors
    /// Refuses a foreign process/thread or exhausted metadata census.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn observe_retained_data(
        &self,
        observer: &mut MetadataObserver,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id() || self.thread != std::thread::current().id() {
            return Err(refused());
        }
        // Failed and partial owners remain measurable; readiness is not a
        // precondition for raw retained custody.
        // The Box root includes every fixed field, including the complete
        // nonserializable ledger and optional cached model. It has no heap child.
        let Self {
            creator: _,
            thread: _,
            preamble: _,
            reservation: _,
            ledger: _,
            raw7: _,
            raw7_bytes,
            raw5: _,
            raw5_bytes,
            sealed: _,
            failed,
            post_record,
            observation: _,
        } = self;
        observer.boxed_value(self)?;
        observer.observe(raw7_bytes)?;
        observer.observe(raw5_bytes)?;
        observer.observe(failed)?;
        observer.observe(&post_record.is_some())
    }
}

impl NativeAckBoot {
    /// Tests the actual private optional owner before new-only limit work.
    ///
    /// This DATA branch grants no suffix action or construction permission.
    ///
    /// # Errors
    /// Refuses a conflicting live boot loan. Old lanes return false directly.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn original_restored_suffix_owner_present_data(
        boot: &Rc<RefCell<Self>>,
    ) -> Result<bool, ProviderError> {
        let owner = boot.try_borrow().map_err(|_| borrowed())?;
        Ok(owner
            .startup
            .as_ref()
            .is_some_and(|startup| startup.restored_suffix.is_some()))
    }

    // Runs only after the actual Commit MAC and full transferred input roster
    // authenticate. The initial launch template is deliberately not a model
    // surrogate. Pure scanners reconstruct the same eight geometry fields before
    // model adoption, then the complete reservation is requoted independently.
    /// Seals geometry from the actual signed Commit input banks before adoption.
    ///
    /// # Errors
    /// Refuses foreign/stale custody, another seal, raw identity or row mismatch,
    /// unsupported actual input geometry, overflow or insufficient reservation.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn seal_original_restored_suffix_model_data(
        boot: &Rc<RefCell<Self>>,
        launch: &PacketNative5SourceLaunch,
        inputs: &crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreSelectedOwnerInputs<'_>,
    ) -> Result<(), ProviderError> {
        let mut owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
        if owner
            .startup
            .as_ref()
            .is_none_or(|startup| startup.restored_suffix.is_none())
        {
            return Ok(());
        }
        owner.authenticate_original_invocation_prepare_target_data()?;
        let Self {
            startup,
            launch_body,
            ..
        } = &mut *owner;
        let Some(state) = startup
            .as_mut()
            .and_then(|startup| startup.restored_suffix.as_mut())
        else {
            return Ok(());
        };
        state.ensure_current()?;
        if state.sealed.is_some() {
            return Err(refused());
        }
        // Every error or unwind after this point leaves the new native owner
        // poisoned. Sealing never refunds or rewrites the finite ledger.
        state.failed = true;
        authenticate_original_native_suffix_preamble_data(
            &state.preamble,
            &state.preamble[328..360],
        )?;
        let nested = nested_launch6_data(launch_body)?;
        if nested.len() != state.raw5_bytes || blake3::hash(nested).as_bytes() != &state.raw5 {
            return Err(refused());
        }
        let maximum = usize::try_from(state.reservation.requested_bytes_data()?)
            .map_err(|_| exhausted())?
            .checked_add(size_of::<PacketNativeRestoredSuffixStartupStorageData>())
            .and_then(|n| {
                n.checked_add(
                    usize::try_from(
                        state
                            .reservation
                            .ingress
                            .declared_counter_scratch_bytes
                            .get(),
                    )
                    .ok()?,
                )
            })
            .ok_or_else(exhausted)?;
        let inputs = crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreSelectedOwnerInputs {
            owner_state: inputs.owner_state,
            journal: inputs.journal,
            control: inputs.control,
            anchor: inputs.anchor,
            maximum_input_bytes: inputs.maximum_input_bytes,
            maximum_before_bytes: inputs.maximum_before_bytes,
            maximum_requested_bytes: maximum,
        };
        let model = crate::reference_packet::service::complete_restore::transfer::complete_restore_invocation_owner_construction_storage_data(&inputs)?;
        let actual = original_native_restored_suffix_startup_storage_data(
            launch,
            nested,
            &model,
            usize::try_from(state.reservation.maximum_originals.get()).map_err(|_| exhausted())?,
            maximum,
        )?;
        if actual.reservation_data() != state.reservation {
            return Err(refused());
        }
        state.sealed = Some(actual);
        state.failed = false;
        state.ensure_current()
    }

    /// Retains a genuine native16 owner before ordinary boot policy construction.
    ///
    /// # Errors
    /// Refuses repeated output, stale inherited custody, a different private
    /// key/birth/purpose/body/row, invalid boot data or insufficient credit.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn prepare_original_restored_suffix_into(
        value: &serde_json::Value,
        launch: &PacketNative5SourceLaunch,
        raw7: &[u8],
        original6: Vec<u8>,
        purpose: PacketNativeInvocationPurposeData,
        startup: &mut super::super::bootstrap_suffix::OriginalRestoredSuffixBootstrap,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(refused());
        }
        startup.ensure_current()?;
        crate::connection::serialized_credit(
            value,
            startup.data.invocation.maximum_boot_bytes as usize,
        )?;
        let data = BootData::deserialize(value).map_err(ContractError::from)?;
        let original = Self::retain_boot_data_into(data, original6, None, completed);
        let result = (|| {
            let mut owner = original.try_borrow_mut().map_err(|_| borrowed())?;
            owner.ensure_origin()?;
            startup.begin_claim(
                owner.data.private_key.as_slice(),
                owner.data.birth_id.as_slice(),
                raw7,
            )?;
            let expected = startup.data.invocation;
            let suffix = startup.data.suffix_reservation;
            if owner.data.schema != PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA
                || purpose.is_original_execution_data()
                || launch.controller_pid.get() != expected.controller_pid
                || launch.controller_uid.get() != expected.controller_uid
                || suffix.maximum_originals.get() > launch.limits.requests.get()
                || blake3::hash(owner.data.private_launch.as_str().as_bytes()).as_bytes()
                    != &expected.private_launch_digest
            {
                return Err(refused());
            }
            purpose.authenticate_target_data(launch)?;
            let fields = owner.data.source_birth.as_object().ok_or_else(refused)?;
            if fields.len() != 19
                || fields.get("schema").and_then(serde_json::Value::as_str)
                    != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
                || PacketNativeInvocationPurposeData::from_original_value_data(
                    fields.get("invocation").ok_or_else(refused)?,
                )? != purpose
            {
                return Err(refused());
            }
            // Both owned canonical outputs are retained in the same boot before
            // any digest, row or subsequent policy validation can refuse.
            owner.source_body = canonical::canonical_json(&owner.data.source_birth)?;
            owner.host_body = canonical::canonical_json(&owner.data.expected_host_registration)?;
            if blake3::hash(&owner.source_body).as_bytes() != &expected.source_digest
                || blake3::hash(&owner.host_body).as_bytes() != &expected.registration_digest
            {
                return Err(refused());
            }
            let maximum = usize::try_from(
                expected
                    .native_birth
                    .requested_peak_data()?
                    .max(expected.private_bootstrap.requested_peak_data()?),
            )
            .map_err(|_| exhausted())?;
            let nested = super::super::bootstrap_suffix::nested_launch5(raw7)?;
            let actual = original_native_invocation_baseline_storage_data(
                &PacketNativeBirthStartupInputs {
                    launch,
                    private_launch: &owner.data.private_launch,
                    encoded_launch: nested,
                    source_birth: &owner.source_body,
                    host_registration: &owner.host_body,
                },
                maximum,
            )?;
            let invocation = original_native_invocation_construction_storage_data(
                &purpose,
                nested,
                actual.maximum_private_boot_body_bytes(),
                maximum,
            )?;
            let carrier = original_native_suffix_construction_storage_data(
                &purpose, nested, &suffix, maximum,
            )?;
            let identity6 = invocation.launch_identity_data();
            if identity6.raw_digest != *blake3::hash(&owner.launch_body).as_bytes()
                || identity6.encoded_bytes != owner.launch_body.len()
                || carrier.launch_identity_data().raw_digest != expected.launch_digest
                || carrier.launch_identity_data().encoded_bytes != raw7.len()
                || invocation.maximum_private_boot_body_bytes()
                    > expected.maximum_boot_bytes as usize
            {
                return Err(refused());
            }
            let scratch = original_native_birth_startup_counter_scratch_data()
                .checked_add(original_native_invocation_counter_scratch_data())
                .and_then(|n| n.checked_add(original_native_suffix_counter_scratch_data()))
                .ok_or_else(exhausted)?;
            let native = row(
                sum(&[
                    actual.retained_requested_bytes(),
                    invocation.native_retained_requested_bytes(),
                    carrier.native_retained_requested_bytes(),
                ])?,
                sum(&[
                    actual.maximum_simultaneous_transient_bytes(),
                    invocation.native_transient_requested_bytes(),
                    carrier.native_transient_requested_bytes(),
                ])?,
                scratch,
            )?;
            let private = row(
                sum(&[
                    actual.private_bootstrap_retained_requested_bytes(),
                    invocation.private_retained_requested_bytes(),
                    carrier.private_retained_requested_bytes(),
                ])?,
                sum(&[
                    actual.private_bootstrap_maximum_simultaneous_transient_bytes(),
                    invocation.private_transient_requested_bytes(),
                    carrier.private_transient_requested_bytes(),
                ])?,
                scratch,
            )?;
            expected.native_birth.authenticate_actual_data(&native)?;
            expected
                .private_bootstrap
                .authenticate_actual_data(&private)?;
            let allocation = PacketNativeStartupAllocation {
                schema: PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA.into(),
                private_bootstrap: expected.private_bootstrap,
                native_birth: expected.native_birth,
                restore_prepare: expected.restore_prepare,
            };
            allocation.validate_data(true)?;
            if serde_json::to_value(&allocation).map_err(ContractError::from)?
                != owner.data.source_birth["native_startup_allocation"]
            {
                return Err(refused());
            }
            let suffix_owner = NativeRestoredSuffixStartupOwner {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                preamble: startup.preamble,
                reservation: suffix,
                ledger: OriginalRestoredSuffixBudget::new_data(suffix)?,
                raw7: expected.launch_digest,
                raw7_bytes: raw7.len(),
                raw5: *blake3::hash(nested).as_bytes(),
                raw5_bytes: nested.len(),
                sealed: None,
                failed: false,
                post_record: None,
                observation: std::rc::Weak::new(),
            };
            // This genuine native Box is installed before ready/policy/model
            // construction. Failures retain it in the same boot and bootstrap.
            owner.startup = Some(native_startup::OriginalNativeStartupBoot {
                restored_suffix: Some(Box::new(suffix_owner)),
                allocation,
                source_digest: expected.source_digest,
                launch_digest: identity6.raw_digest,
                birth_id: expected.birth_id,
                native_birth_issued: true,
                baseline_complete: false,
                prepare_startup_issued: false,
            });
            drop(owner);
            Self::prepare_retained_data(&original, launch, Some(purpose))?;
            startup.complete_claim()
        })();
        if result.is_err() {
            startup.failed = true;
            if let Ok(mut owner) = original.try_borrow_mut() {
                if let Some(suffix) = owner
                    .startup
                    .as_mut()
                    .and_then(|startup| startup.restored_suffix.as_mut())
                {
                    suffix.failed = true;
                    suffix.ledger.interrupt_data();
                }
            }
        }
        result
    }
}

fn row(
    retained: usize,
    transient: usize,
    scratch: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    Ok(PacketNativeStartupAllocationRow {
        retained_requested_bytes: quantity(retained)?,
        maximum_simultaneous_transient_bytes: quantity(transient)?,
        declared_counter_scratch_bytes: quantity(scratch)?,
    })
}

fn quantity(value: usize) -> Result<U64, ProviderError> {
    Ok(U64::new(u64::try_from(value).map_err(|_| exhausted())?))
}

fn sum(terms: &[usize]) -> Result<usize, ProviderError> {
    let mut total = 0usize;
    for term in terms {
        total = total.checked_add(*term).ok_or_else(exhausted)?;
    }
    Ok(total)
}

fn refused() -> ProviderError {
    ProviderError::Correlation("restored suffix16 native owner differs")
}

fn borrowed() -> ProviderError {
    ProviderError::Conflict("restored suffix16 native owner borrowed")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("restored suffix16 native owner credit")
}

/// Returns the fixed native Box payload independently added before birth.
pub(crate) fn original_restored_suffix_native_header_data() -> usize {
    size_of::<NativeRestoredSuffixStartupOwner>()
}

/// Names the defining boot, scanner, comparison and witness views before allocation.
pub(crate) fn original_restored_suffix_native_counter_scratch_data() -> usize {
    let owner_loans = size_of::<Option<&native_startup::OriginalNativeStartupBoot>>()
        + size_of::<&Box<NativeRestoredSuffixStartupOwner>>()
        + size_of::<&mut Box<NativeRestoredSuffixStartupOwner>>()
        + size_of::<Option<&Box<NativeRestoredSuffixStartupOwner>>>()
        + size_of::<Option<&mut Box<NativeRestoredSuffixStartupOwner>>>()
        + size_of::<Result<&Box<NativeRestoredSuffixStartupOwner>, ProviderError>>()
        + size_of::<Result<&mut Box<NativeRestoredSuffixStartupOwner>, ProviderError>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeAckBoot>, ProviderError>>();
    let input_loans = size_of::<Option<&serde_json::Map<String, serde_json::Value>>>()
        + size_of::<&mut crate::protocol_snapshot::owned11::OriginalOwned11Fields<'static>>()
        + size_of::<Rc<RefCell<NativeAckBoot>>>()
        + size_of::<&mut Option<Rc<RefCell<NativeAckBoot>>>>()
        + size_of::<blake3::Hash>()
        + size_of::<&[u8; 32]>();
    let construction_views = size_of::<NativeRestoredSuffixStartupOwner>()
        + size_of::<Box<NativeRestoredSuffixStartupOwner>>()
        + size_of::<Option<Box<NativeRestoredSuffixStartupOwner>>>()
        + size_of::<OriginalRestoredSuffixBudget>()
        + size_of::<Result<OriginalRestoredSuffixBudget, ProviderError>>()
        + size_of::<PacketNativeSuffixConstructionStorageData>()
        + size_of::<Result<PacketNativeSuffixConstructionStorageData, ProviderError>>()
        + size_of::<PacketNativeInvocationConstructionStorageData>()
        + size_of::<Result<PacketNativeInvocationConstructionStorageData, ProviderError>>()
        + size_of::<PacketNativeBirthStartupStorageData>()
        + size_of::<Result<PacketNativeBirthStartupStorageData, ProviderError>>()
        + size_of::<PacketNativeSuffixPreambleData>()
        + size_of::<PacketNativeInvocationPreambleData>();

    let allocation_and_return_views = size_of::<std::cell::RefMut<'static, NativeAckBoot>>()
        + size_of::<Result<std::cell::RefMut<'static, NativeAckBoot>, std::cell::BorrowMutError>>()
        + size_of::<PacketNativeStartupAllocation>()
        + size_of::<PacketNativeStartupAllocationRow>() * 2
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + size_of::<Result<U64, ProviderError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<BootData>()
        + size_of::<Result<BootData, ContractError>>();

    let decoded_owner_views = size_of::<Result<BootData, serde_json::Error>>()
        + size_of::<Result<serde_json::Value, ContractError>>()
        + size_of::<Result<serde_json::Value, serde_json::Error>>()
        + size_of::<&NativeRestoredSuffixStartupOwner>()
        + size_of::<&mut NativeRestoredSuffixStartupOwner>()
        + size_of::<Option<&NativeRestoredSuffixStartupOwner>>()
        + size_of::<Option<&mut NativeRestoredSuffixStartupOwner>>()
        + size_of::<Result<&NativeRestoredSuffixStartupOwner, ProviderError>>()
        + size_of::<Result<&mut NativeRestoredSuffixStartupOwner, ProviderError>>()
        + size_of::<Result<Vec<u8>, ContractError>>()
        + size_of::<Vec<u8>>()
        + size_of::<&serde_json::Value>()
        + size_of::<&serde_json::Map<String, serde_json::Value>>()
        + size_of::<Result<&serde_json::Map<String, serde_json::Value>, ProviderError>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<PacketNativeInvocationPurposeData, ProviderError>>()
        + size_of::<Result<PacketNativeStartupAllocation, ProviderError>>()
        + size_of::<Option<&serde_json::Value>>()
        + size_of::<Result<&serde_json::Value, ProviderError>>()
        + size_of::<&native_startup::OriginalNativeStartupBoot>();

    let model_and_scan_views = size_of::<&mut native_startup::OriginalNativeStartupBoot>()
        + size_of::<Option<&mut native_startup::OriginalNativeStartupBoot>>()
        + size_of::<PacketNativeRestoredSuffixStartupStorageData>()
        + size_of::<Option<PacketNativeRestoredSuffixStartupStorageData>>()
        + size_of::<Result<PacketNativeRestoredSuffixStartupStorageData, ProviderError>>()
        + size_of::<Result<PacketRestoredSuffixReservationData, ProviderError>>()
        + size_of::<std::rc::Weak<RefCell<NativeRestorationObservationAttempt>>>()
        + size_of::<Option<Rc<RefCell<NativeRestorationObservationAttempt>>>>()
        + size_of::<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreSelectedOwnerInputs<'static>>() * 2
        + size_of::<&crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreSelectedOwnerInputs<'static>>()
        + size_of::<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage>()
        + size_of::<Result<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage, ProviderError>>()
        + size_of::<crate::protocol_snapshot::owned11::OriginalOwned11Fields<'static>>()
        + size_of::<Result<crate::protocol_snapshot::owned11::OriginalOwned11Fields<'static>, ProviderError>>()
        + size_of::<&[u8]>() * 4
        + size_of::<Result<&[u8], ProviderError>>()
        + size_of::<Result<u64, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<&PacketNativeStartupAllocationRow>()
        + crate::reference_packet::service::complete_restore::transfer::complete_restore_selected_owner_construction_counter_scratch_data()
        + size_of::<&crate::reference_packet::service::complete_restore::restoration_observe::PacketRestorationObservationRequest>()
        + size_of::<&crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationAllocationRow>()
        + size_of::<&PacketNativeStartupAllocationRow>()
        + size_of::<&str>()
        + size_of::<crucible_node_contract::U64>()
        + size_of::<Result<u64, ProviderError>>() * 2
        + original_restored_suffix_post_observation_counter_scratch_data()
        + size_of::<[usize; 3]>()
        + size_of::<&[usize]>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<&usize>();

    owner_loans
        + input_loans
        + construction_views
        + allocation_and_return_views
        + decoded_owner_views
        + model_and_scan_views
}

fn nested_launch6_data(raw: &[u8]) -> Result<&[u8], ProviderError> {
    let mut fields = crate::protocol_snapshot::owned11::OriginalOwned11Fields::object(raw)?;
    fields.named("invocation")?;
    let nested = fields.named("launch")?;
    if fields.named("schema_version")? != b"6" {
        return Err(refused());
    }
    fields.finish()?;
    Ok(nested)
}

// This projection is specific to the closed first-Observe demand. It never
// constructs a startup row, native owner or witness from restoration DATA.
fn authenticate_initial_observation_projection_data(
    admitted: &PacketNativeStartupAllocationRow,
    schema: &str,
    maximum_items: crucible_node_contract::U64,
    actual: &crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationAllocationRow,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::complete_restore::restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE;

    if schema != PACKET_RESTORATION_OBSERVE_FEATURE || maximum_items.get() != 1 {
        return Err(refused());
    }
    admitted.requested_peak_data()?;
    actual.requested_bytes_data()?;
    if actual.retained_requested_bytes > admitted.retained_requested_bytes
        || actual.maximum_simultaneous_transient_bytes
            > admitted.maximum_simultaneous_transient_bytes
        || actual.declared_counter_scratch_bytes > admitted.declared_counter_scratch_bytes
    {
        return Err(ProviderError::ResourceExhausted(
            "restored suffix initial observation demand exceeds independent window",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod witness_projection_tests {
    use super::*;
    use crate::reference_packet::service::complete_restore::{
        activation::PacketRestorationActivationAllocationRow,
        restoration_observe::PACKET_RESTORATION_OBSERVE_FEATURE,
    };
    use crucible_node_contract::U64;

    #[test]
    fn first_observation_demand_refuses_other_domains_and_each_short_axis() {
        let actual = PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(19),
            maximum_simultaneous_transient_bytes: U64::new(23),
            declared_counter_scratch_bytes: U64::new(29),
        };
        let admitted = PacketNativeStartupAllocationRow {
            retained_requested_bytes: actual.retained_requested_bytes,
            maximum_simultaneous_transient_bytes: actual.maximum_simultaneous_transient_bytes,
            declared_counter_scratch_bytes: actual.declared_counter_scratch_bytes,
        };
        let check = |admitted: &PacketNativeStartupAllocationRow, schema, count| {
            authenticate_initial_observation_projection_data(admitted, schema, U64::new(count), &actual)
        };

        // Only inert demand correspondence passes here; no native owner,
        // signed request or positive witness is created by this control.
        check(&admitted, PACKET_RESTORATION_OBSERVE_FEATURE, 1).unwrap();
        assert!(check(&admitted, "source-owned.packet-restoration-activation/1", 1).is_err());
        assert!(check(&admitted, PACKET_RESTORATION_OBSERVE_FEATURE, 0).is_err());
        assert!(check(&admitted, PACKET_RESTORATION_OBSERVE_FEATURE, 2).is_err());

        let mut short = admitted;
        short.retained_requested_bytes = U64::new(18);
        assert!(check(&short, PACKET_RESTORATION_OBSERVE_FEATURE, 1).is_err());
        short = admitted;
        short.maximum_simultaneous_transient_bytes = U64::new(22);
        assert!(check(&short, PACKET_RESTORATION_OBSERVE_FEATURE, 1).is_err());
        short = admitted;
        short.declared_counter_scratch_bytes = U64::new(28);
        assert!(check(&short, PACKET_RESTORATION_OBSERVE_FEATURE, 1).is_err());

        let empty = PacketRestorationActivationAllocationRow {
            retained_requested_bytes: U64::new(0),
            ..actual
        };
        assert!(authenticate_initial_observation_projection_data(
            &admitted,
            PACKET_RESTORATION_OBSERVE_FEATURE,
            U64::new(1),
            &empty,
        ).is_err());
    }
}
