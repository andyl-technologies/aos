//! Installs the same nested suffix owners under genuine prefix17 custody.
//!
//! The complete wrapper8 is authenticated once. Its derived nested7/6 bodies
//! retain only their original DATA identities; no old prefix MAC is fabricated.
//! The new Capture reserve is retained in Boot before baseline construction.

use super::*;

impl NativeAckBoot {
    /// Retains a genuine native17 owner before ordinary boot policy construction.
    ///
    /// # Errors
    /// Refuses repeated output, stale inherited custody, a different private
    /// key/birth/purpose/body/row, invalid boot data or insufficient credit.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn prepare_original_restored_settled_into(
        value: &serde_json::Value,
        launch: &PacketNative5SourceLaunch,
        raw8: &[u8],
        raw7: &[u8],
        original6: Vec<u8>,
        purpose: PacketNativeInvocationPurposeData,
        existing_rows: &PacketRestoredSettledNativeExistingRowsData,
        startup: &mut super::super::super::bootstrap_settled::OriginalRestoredSettledBootstrap,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() {
            return Err(refused());
        }
        startup.ensure_current()?;
        crate::connection::serialized_credit(
            value,
            startup.data.suffix.invocation.maximum_boot_bytes as usize,
        )?;
        let data = BootData::deserialize(value).map_err(ContractError::from)?;
        let original = Self::retain_boot_data_into(data, original6, None, completed);
        let result = (|| {
            let mut owner = original.try_borrow_mut().map_err(|_| borrowed())?;
            owner.ensure_origin()?;
            {
                let NativeAckBoot {
                    data,
                    restored_settled,
                    ..
                } = &mut *owner;
                super::super::super::restored_settled::NativeRestoredSettledCaptureOwner::retain_from_bootstrap_into(
                    startup, &original, data.private_key.as_slice(), data.birth_id.as_slice(), raw8,
                    existing_rows, purpose, restored_settled,
                )?;
            }
            let expected = startup.data.suffix.invocation;
            let suffix = startup.data.suffix.suffix_reservation;
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
            let nested = super::super::super::bootstrap_suffix::nested_launch5(raw7)?;
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
                || carrier.launch_identity_data().raw_digest != *blake3::hash(raw7).as_bytes()
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
                preamble: RestoredSuffixPreamble::Settled17(*startup.preamble_data()),
                reservation: suffix,
                ledger: OriginalRestoredSuffixBudget::new_data(suffix)?,
                observe_attempts: Vec::new(),
                producer_attempts: Vec::new(),
                raw7: *blake3::hash(raw7).as_bytes(),
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
            startup.interrupt();
            if let Ok(mut owner) = original.try_borrow_mut() {
                if let Some(capture) = owner.restored_settled.as_mut() {
                    capture.interrupt();
                }
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
