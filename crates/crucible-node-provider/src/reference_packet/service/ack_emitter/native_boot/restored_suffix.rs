//! Retains the actual startup16 reservation separately from every old boot lane.
//!
//! Its constructor requires the same authenticated inherited prefix and complete
//! Source15/boot7 correspondence. Cached archive geometry is unavailable at boot;
//! it is sealed later from the actual signed restoration input banks. Numeric
//! rows alone enable neither an Endpoint action nor a Capture codec. The paired
//! recurring Observe route additionally authenticates current custody and spends
//! its independent action window before producing a new native proof.

use super::*;
use crate::connection::{Connection, ExchangeRecord, ProviderStream};
use crate::reference_packet::control::PacketControl;
use crate::reference_packet::service::native_startup::*;
use crate::retained_metadata::MetadataObserver;
use std::mem::size_of;

/// Retains the independently received reservation, fixed ledger and actual links.
pub(in crate::reference_packet::service::ack_emitter::native_boot) struct NativeRestoredSuffixStartupOwner
{
    creator: u32,
    thread: ThreadId,
    preamble: RestoredSuffixPreamble,
    reservation: PacketRestoredSuffixReservationData,
    ledger: OriginalRestoredSuffixBudget,
    observe_attempts: Vec<Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>,
    producer_attempts: Vec<Rc<RefCell<NativeRestoredProducerAttempt>>>,
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
    /// Borrows the exact frame bound sealed from the actual transferred inputs.
    ///
    /// # Errors
    /// Refuses failed, foreign or unsealed native custody and integer overflow.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn original_frame_bytes_data(
        &self,
    ) -> Result<u64, ProviderError> {
        self.ensure_current()?;
        Ok(
            u64::try_from(self.sealed.as_ref().ok_or_else(refused)?.frame_bytes_data())
                .map_err(|_| exhausted())?,
        )
    }

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
    /// Refuses failed or unsealed state and any short independent axis.
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

    /// Bounds the same scanner and quote phase used when actual Commit sealed geometry.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn model_quote_maximum_data(
        &self,
    ) -> Result<usize, ProviderError> {
        self.ensure_current()?;
        usize::try_from(self.reservation.requested_bytes_data()?)
            .map_err(|_| exhausted())?
            .checked_add(size_of::<PacketNativeRestoredSuffixStartupStorageData>())
            .and_then(|n| {
                n.checked_add(
                    usize::try_from(
                        self.reservation
                            .ingress
                            .declared_counter_scratch_bytes
                            .get(),
                    )
                    .ok()?,
                )
            })
            .ok_or_else(exhausted)
    }

    /// Requotes the same actual transferred geometry before debiting native action work.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn observation_row_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        encoded6: &[u8],
        model: &crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage,
        observe: &crate::bodies::ObserveRequest,
    ) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        self.ensure_current()?;
        let nested = nested_launch6_data(encoded6)?;
        let maximum = self.model_quote_maximum_data()?;
        let sealed = self.sealed.as_ref().ok_or_else(refused)?;
        sealed.authenticate_same_inputs_data(
            launch,
            nested,
            model,
            usize::try_from(self.reservation.maximum_originals.get()).map_err(|_| exhausted())?,
            maximum,
        )?;
        original_native_restored_suffix_observation_required_storage_data(
            sealed, launch, nested, observe, maximum,
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

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn published_producer_upload_extent_data(
        &self,
        transfer: &str,
    ) -> Result<usize, ProviderError> {
        self.ensure_current()?;
        let mut extent = None;
        for previous in &self.producer_attempts {
            if let Some(actual) = previous
                .try_borrow()
                .map_err(|_| borrowed())?
                .published_upload_extent_data(transfer)?
            {
                if extent.is_some_and(|earlier| earlier != actual) {
                    return Err(refused());
                }
                extent = Some(actual);
            }
        }
        extent.ok_or_else(refused)
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
        // nonserializable ledger and optional cached model. Each dynamic
        // recurring receive owner is observed independently below.
        let Self {
            creator: _,
            thread: _,
            preamble: _,
            reservation: _,
            ledger: _,
            observe_attempts,
            producer_attempts,
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
        observer.observe(&post_record.is_some())?;
        observer.vector::<Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>(
            observe_attempts.capacity(),
        )?;
        for attempt in observe_attempts {
            observer.shared_original(crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredSuffixObservationAttempt, attempt.as_ref())?;
            attempt
                .try_borrow()
                .map_err(|_| borrowed())?
                .observe_retained_data(observer)?;
        }
        observer
            .vector::<Rc<RefCell<NativeRestoredProducerAttempt>>>(producer_attempts.capacity())?;
        for attempt in producer_attempts {
            observer.shared_original(crate::retained_metadata::aliases::MetadataSharedKind::NativeRestoredProducerAttempt, attempt.as_ref())?;
            attempt
                .try_borrow()
                .map_err(|_| borrowed())?
                .observe_retained_data(observer)?;
        }
        Ok(())
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

    /// Selects recurring receive only after the actual signed first publication.
    ///
    /// # Errors
    /// Refuses a foreign process/thread, conflicting loan or failed native owner.
    pub(crate) fn original_restored_suffix_observation_ready_data(
        boot: &Rc<RefCell<Self>>,
    ) -> Result<bool, ProviderError> {
        let owner = boot.try_borrow().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        let Some(state) = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
        else {
            return Ok(false);
        };
        state.ensure_current()?;
        Ok(state.post_record.is_some())
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
        state.preamble.authenticate_data()?;
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
                &purpose,
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
                preamble: RestoredSuffixPreamble::Original16(startup.preamble),
                reservation: suffix,
                ledger: OriginalRestoredSuffixBudget::new_data(suffix)?,
                observe_attempts: Vec::new(),
                producer_attempts: Vec::new(),
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

    producer::counter_scratch_data()
        + owner_loans
        + original_native_restored_suffix_observation_counter_scratch_data()
        + size_of::<Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>()
        + size_of::<Option<&Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>>()
        + size_of::<Result<&Rc<RefCell<NativeRestoredSuffixObserveAttempt>>, ProviderError>>()
        + size_of::<std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>>()
        + size_of::<std::cell::RefMut<'static, NativeRestoredSuffixObserveAttempt>>()
        + size_of::<
            Result<
                std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>,
                std::cell::BorrowError,
            >,
        >()
        + size_of::<
            Result<std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>, ProviderError>,
        >()
        + size_of::<
            Result<
                std::cell::RefMut<'static, NativeRestoredSuffixObserveAttempt>,
                std::cell::BorrowMutError,
            >,
        >()
        + size_of::<
            Result<std::cell::RefMut<'static, NativeRestoredSuffixObserveAttempt>, ProviderError>,
        >()
        + size_of::<std::cell::Ref<'static, Envelope>>()
        + size_of::<Result<std::cell::Ref<'static, Envelope>, ProviderError>>()
        + size_of::<
            Result<
                std::cell::Ref<'static, Envelope>,
                std::cell::Ref<'static, NativeRestoredSuffixObserveAttempt>,
            >,
        >()
        + size_of::<std::cell::Cell<bool>>() * 3
        + size_of::<std::cell::Cell<Option<usize>>>()
        + size_of::<Result<PacketNativeStartupAllocationRow, ProviderError>>()
        + original_restored_suffix_observe_custody_counter_scratch_data()
        + size_of::<OriginalRestoredSuffixObserveRead<'static>>()
        + size_of::<Result<OriginalRestoredSuffixObserveRead<'static>, ProviderError>>()
        + size_of::<&OriginalRestoredSuffixObserveRead<'static>>()
        + size_of::<&OriginalRestoredSuffixPostObservation>()
        + size_of::<Option<&NativeRestoredSuffixObserveAttempt>>()
        + size_of::<Option<&mut NativeRestoredSuffixObserveAttempt>>()
        + size_of::<Result<&NativeRestoredSuffixObserveAttempt, ProviderError>>()
        + size_of::<Result<&mut NativeRestoredSuffixObserveAttempt, ProviderError>>()
        + size_of::<std::cell::Ref<'static, NativeAckBoot>>()
        + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, std::cell::BorrowError>>()
        + size_of::<Result<std::cell::Ref<'static, NativeAckBoot>, ProviderError>>()
        + size_of::<Vec<Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>>()
        + size_of::<std::slice::Iter<'static, Rc<RefCell<NativeRestoredSuffixObserveAttempt>>>>()
        + size_of::<&NativeRestoredSuffixObserveAttempt>()
        + size_of::<std::collections::TryReserveError>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
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

/// Borrows a spent receive slot under the actual published-first witness.
///
/// Dropping an unfinished scope poisons the owner and budget. Only complete
/// current proof, terminal and sent ACK publication reopen the ledger; raw or
/// typed receive success alone cannot do so.
pub(crate) struct OriginalRestoredSuffixObserveRead<'a> {
    witness: &'a OriginalRestoredSuffixPostObservation,
    boot: Rc<RefCell<NativeAckBoot>>,
    index: usize,
    frame: usize,
    attempt: Rc<RefCell<NativeRestoredSuffixObserveAttempt>>,
    receive_started: std::cell::Cell<bool>,
    incoming_slot: std::cell::Cell<Option<usize>>,
    action_started: std::cell::Cell<bool>,
    completed: std::cell::Cell<bool>,
}

impl<'a> OriginalRestoredSuffixObserveRead<'a> {
    /// Retains one irrevocably spent original under the actual received owner.
    ///
    /// # Errors
    /// Refuses stale custody, a depleted axis/count or failed slot allocation.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn retain_data(
        witness: &'a OriginalRestoredSuffixPostObservation,
        boot: &Rc<RefCell<NativeAckBoot>>,
        frame: usize,
    ) -> Result<Self, ProviderError> {
        let ingress = original_restored_suffix_observe_ingress_row_data(frame)?;
        let mut owner = boot.try_borrow_mut().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let state = owner
            .startup
            .as_mut()
            .and_then(|startup| startup.restored_suffix.as_mut())
            .ok_or_else(refused)?;
        state.ensure_current()?;
        state.reservation_data()?;
        // Spend first. A short row, failed allocation or later read cannot
        // obtain another slot or refund this native original's debit.
        state.failed = true;
        let ordinal = state.ledger.begin_ingress_data(ingress)?;
        state
            .observe_attempts
            .try_reserve_exact(1)
            .map_err(|_| exhausted())?;
        let index = state.observe_attempts.len();
        let attempt = Rc::new(RefCell::new(NativeRestoredSuffixObserveAttempt::new_data(
            ordinal,
        )));
        state.observe_attempts.push(Rc::clone(&attempt));
        state.failed = false;
        drop(owner);
        Ok(Self {
            witness,
            boot: Rc::clone(boot),
            index,
            frame,
            attempt,
            receive_started: std::cell::Cell::new(false),
            incoming_slot: std::cell::Cell::new(None),
            action_started: std::cell::Cell::new(false),
            completed: std::cell::Cell::new(false),
        })
    }

    /// Starts one receive on the same actual admitted native connection.
    ///
    /// # Errors
    /// Refuses repeated, completed, foreign or conflicting native custody.
    pub(crate) fn begin_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        if self.receive_started.replace(true) || self.completed.get() {
            return Err(refused());
        }
        self.authenticate_receive_data(connection)
    }

    /// Checks the same retained attempt, boot and current negotiated authority.
    ///
    /// # Errors
    /// Refuses missing, failed, foreign, completed or conflicting custody.
    pub(crate) fn authenticate_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        let admission = connection.original_native_owned11_admission()?;
        admission.authenticate_current(connection)?;
        if !Rc::ptr_eq(&self.boot, &admission.boot) {
            return Err(refused());
        }
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let state = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?;
        state.ensure_current()?;
        if !self.receive_started.get()
            || self.completed.get()
            || state
                .observe_attempts
                .get(self.index)
                .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Borrows the exact original retained before policy and typed checks.
    ///
    /// # Errors
    /// Refuses missing, failed or conflicting attempt custody.
    pub(crate) fn original_data(&self) -> Result<std::cell::Ref<'_, Envelope>, ProviderError> {
        let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
        attempt.original_data()?;
        std::cell::Ref::filter_map(attempt, |attempt| attempt.original_data().ok())
            .map_err(|_| refused())
    }

    /// Completes receive only for the actual fully retained incoming literal.
    ///
    /// # Errors
    /// Refuses repeated completion, stale custody or canonical frame mismatch.
    pub(crate) fn complete_receive_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
    ) -> Result<(), ProviderError> {
        self.authenticate_receive_data(connection)?;
        if self.incoming_slot.get().is_some() {
            return Err(refused());
        }
        let original = self.original_data()?;
        let slot = connection.original_restored_suffix_observation_literal_slot_data(&original)?;
        self.incoming_slot.set(Some(slot));
        Ok(())
    }

    /// Debits complete native proof and publication demand before dispatch.
    ///
    /// # Errors
    /// Refuses another dispatch, changed current model/owners or any short axis.
    pub(crate) fn begin_dispatch_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        self.authenticate_receive_data(connection)?;
        if self.action_started.replace(true) {
            return Err(refused());
        }
        self.witness
            .authenticate_current_data(connection, control, records)?;
        {
            let original = self.original_data()?;
            connection.authenticate_original_restored_suffix_observation_literal_data(
                &original,
                self.incoming_slot.get().ok_or_else(refused)?,
            )?;
        }
        let required = {
            let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
            self.witness
                .observation_row_data(connection, attempt.body_data()?)?
        };
        {
            let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
                .ok_or_else(refused)?;
            state.ensure_current()?;
            state.failed = true;
            state.ledger.begin_action_data(required)?;
            self.attempt
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .begin_dispatch_data()?;
            state.failed = false;
        }
        self.witness
            .authenticate_current_data(connection, control, records)
    }

    /// Authenticates the actual dispatched original under the same live Control.
    ///
    /// # Errors
    /// Refuses changed original identity, physical release, scope or live owners.
    pub(crate) fn authenticate_control_request_data(
        &self,
        original: &Envelope,
        selection: &crate::reference_packet::control::PacketControlSelection,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        if !self.action_started.get() || self.completed.get() {
            return Err(refused());
        }
        let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
        if !std::ptr::eq(attempt.original_data()?, original) {
            return Err(refused());
        }
        attempt.authenticate_dispatched_data()?;
        self.witness
            .authenticate_observe_control_data(original, selection, control)
    }

    /// Retains the real terminal before checking complete literal ACK publication.
    ///
    /// # Errors
    /// Refuses another completion, changed terminal/proof/currency, unsent frames
    /// or incomplete ACK publication. Every partial remains owned and spent.
    pub(crate) fn complete_publication_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<(), ProviderError> {
        if !self.action_started.get() || self.completed.get() {
            return Err(refused());
        }
        let record = records.last().ok_or_else(refused)?;
        let (terminal_index, terminal) = {
            let original = self.original_data()?;
            crate::connection::original_restored_response_data(&original, record.originals())?
        };
        self.attempt
            .try_borrow_mut()
            .map_err(|_| borrowed())?
            .retain_terminal_data(terminal)?;
        {
            let attempt = self.attempt.try_borrow().map_err(|_| borrowed())?;
            control.authenticate_original_restoration_observation_terminal_data(
                attempt.original_data()?,
                terminal,
            )?;
            connection.authenticate_original_restored_suffix_observation_literal_data(
                attempt.original_data()?,
                self.incoming_slot.get().ok_or_else(refused)?,
            )?;
        }
        if record.sent() != record.originals().len() {
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
        self.witness
            .authenticate_current_data(connection, control, records)?;
        self.authenticate_receive_data(connection)?;
        let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
        let state = owner
            .startup
            .as_mut()
            .and_then(|startup| startup.restored_suffix.as_mut())
            .ok_or_else(refused)?;
        state.failed = true;
        self.attempt
            .try_borrow_mut()
            .map_err(|_| borrowed())?
            .complete_publication_data()?;
        state.ledger.complete_publication_data()?;
        state.failed = false;
        self.completed.set(true);
        Ok(())
    }

    /// Retains the actual raw original before route or typed decoding can fail.
    ///
    /// This stage performs no model callback, native proof encoding or send.
    /// The same actual first-observation witness is rechecked around decoding;
    /// future advanced inventory must use a distinct current-proof validator.
    ///
    /// # Errors
    /// Refuses another route/frontier, raw or typed rejection, conflicting loans
    /// and any actual first-witness/current Control failure.
    pub(crate) fn retain_original_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
        original: Envelope,
    ) -> Result<(), ProviderError> {
        {
            let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
                .ok_or_else(refused)?;
            state.ensure_current()?;
            state
                .observe_attempts
                .get(self.index)
                .filter(|attempt| Rc::ptr_eq(attempt, &self.attempt))
                .ok_or_else(refused)?
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .retain_original_data(original)?;
        }
        // No boot RefMut crosses the witness's actual same-owner recheck.
        self.witness
            .authenticate_current_data(connection, control, records)?;
        {
            let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_ref()
                .and_then(|startup| startup.restored_suffix.as_ref())
                .ok_or_else(refused)?;
            let original = state
                .observe_attempts
                .get(self.index)
                .filter(|attempt| Rc::ptr_eq(attempt, &self.attempt))
                .ok_or_else(refused)?
                .try_borrow()
                .map_err(|_| borrowed())?;
            let original = original.original_data()?;
            self.witness
                .authenticate_observe_original_identity_data(original)?;
        }
        {
            let mut owner = self.boot.try_borrow_mut().map_err(|_| borrowed())?;
            let state = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
                .ok_or_else(refused)?;
            state
                .observe_attempts
                .get(self.index)
                .filter(|attempt| Rc::ptr_eq(attempt, &self.attempt))
                .ok_or_else(refused)?
                .try_borrow_mut()
                .map_err(|_| borrowed())?
                .decode_body_data(self.frame)?;
            state.failed = false;
        }
        self.witness
            .authenticate_current_data(connection, control, records)
    }
}

impl Drop for OriginalRestoredSuffixObserveRead<'_> {
    fn drop(&mut self) {
        if self.completed.get() {
            return;
        }

        if let Ok(mut owner) = self.boot.try_borrow_mut() {
            if let Some(state) = owner
                .startup
                .as_mut()
                .and_then(|startup| startup.restored_suffix.as_mut())
            {
                state.failed = true;
                state.ledger.interrupt_data();
                if let Ok(mut attempt) = self.attempt.try_borrow_mut() {
                    attempt.interrupt_data();
                }
            }
        }
    }
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
            authenticate_initial_observation_projection_data(
                admitted,
                schema,
                U64::new(count),
                &actual,
            )
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
        assert!(
            authenticate_initial_observation_projection_data(
                &admitted,
                PACKET_RESTORATION_OBSERVE_FEATURE,
                U64::new(1),
                &empty,
            )
            .is_err()
        );
    }
}

#[path = "restored_suffix/producer.rs"]
mod producer;
pub(crate) use producer::OriginalRestoredProducerRead;

#[path = "restored_suffix/settled.rs"]
mod settled;

#[path = "restored_suffix/settled_startup.rs"]
mod settled_startup;

/// Keeps the actual authenticated prefix family instead of forging an old MAC.
enum RestoredSuffixPreamble {
    Original16([u8; ORIGINAL_NATIVE_RESTORED_SUFFIX_PREAMBLE_BYTES]),
    Settled17([u8; ORIGINAL_NATIVE_RESTORED_SETTLED_PREAMBLE_BYTES]),
}

impl RestoredSuffixPreamble {
    fn authenticate_data(&self) -> Result<(), ProviderError> {
        match self {
            Self::Original16(bytes) => {
                authenticate_original_native_suffix_preamble_data(bytes, &bytes[328..360])
            }
            Self::Settled17(bytes) => {
                authenticate_original_native_settled_preamble_data(bytes, &bytes[504..536])
            }
        }
    }

    fn bytes_data(&self) -> &[u8] {
        match self {
            Self::Original16(bytes) => bytes,
            Self::Settled17(bytes) => bytes,
        }
    }

    fn is_settled17_data(&self) -> bool {
        matches!(self, Self::Settled17(_))
    }
}
