//! Builds one finite future proof, then signs only the actual installed hold.
//!
//! The prebuilt body is inert until the same captured model and original socket
//! have moved behind the independent physical hold. Response assignment follows
//! the completed proof exchange and is authenticated again before receipt MAC.

use super::*;
use crate::bodies::PrepareRestoreResult;
use crucible_node_format::Validate;

pub(super) fn prepare_gate_evidence(
    attempt: &Rc<RefCell<NativeCompleteRestoreAttempt>>,
) -> Result<(), ProviderError> {
    let mut flight = attempt.try_borrow_mut().map_err(|_| borrowed())?;
    flight.ensure_origin()?;
    if flight.gate_evidence.is_some() || !flight.receipt_body.is_empty() {
        return Err(refused());
    }
    let original = flight.original.as_ref().ok_or_else(refused)?;
    let request = flight.request.as_ref().ok_or_else(refused)?;
    let target = &request.prepare.restoration;
    let (local_cursor, inventory_hash) = flight
        .prepared_model
        .as_ref()
        .ok_or_else(refused)?
        .prepared_boundary()?;
    let complete_commit = bounded_canonical(original, 65_536)?;
    let context = bounded_canonical(
        flight.context.as_ref().ok_or_else(refused)?,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
    )?;
    let body = PacketNativeRestoredCommitHold {
        schema: "source-owned.packet-restored-commit-held/12".into(),
        native_pid: U64::new(u64::from(std::process::id())),
        target_world: target.target_world.clone(),
        target_owner: target.target_owner.clone(),
        target_owner_binding: target.target_owner_binding.clone(),
        target_activation: target.target_activation.clone(),
        target_generation: target.target_generation,
        captured_owner_state: target.owner_state.clone(),
        captured_control: request.prepare.native_control.clone(),
        captured_journal: target.journal.clone(),
        mapping: target.mapping.clone(),
        restore_commit: canonical::content_ref(&complete_commit, "application/json")?,
        context_digest: digest(&context),
        local_cursor,
        inventory_hash: inventory_hash.clone(),
        physical_gate_held: true,
    };
    body.validate_data()?;
    let encoded = bounded_canonical(&body, maximum_complete_restore_held_evidence_bytes()?)?;
    let reference = canonical::content_ref(&encoded, "application/json")?;
    flight.gate_evidence = Some((reference, encoded));
    flight.gate_data = Some(body);
    flight
        .receipt_body
        .try_reserve_exact(MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)
        .map_err(|_| ProviderError::ResourceExhausted("native Commit receipt bank"))?;
    if flight.receipt_body.capacity() != MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES {
        return Err(refused());
    }
    flight
        .response_body
        .try_reserve_exact(65_536)
        .map_err(|_| ProviderError::ResourceExhausted("native completed Commit bank"))?;
    if flight.response_body.capacity() != 65_536 {
        return Err(refused());
    }
    Ok(())
}

/// Retains the actual completed pair for later native evidence, without a socket.
pub(crate) struct NativeRestoredControlEvidence {
    boot: Rc<RefCell<NativeAckBoot>>,
    attempt: Rc<RefCell<NativeCompleteRestoreAttempt>>,
    hold: Rc<PacketCompleteRestorePhysicalHold>,
}

impl NativeRestoredControlEvidence {
    pub(crate) fn wrap(
        &self,
        native_receipt: crate::reference_packet::control::PacketNative5Record,
        prospective_release: bool,
    ) -> Result<PacketNativeRestoredRecord, ProviderError> {
        let boot = self.boot.try_borrow().map_err(|_| borrowed())?;
        boot.ensure_origin()?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if boot
            .restoration
            .as_ref()
            .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
            || flight
                .physical_hold
                .as_ref()
                .is_none_or(|hold| !Rc::ptr_eq(hold, &self.hold))
            || !flight.receipt_started
            || flight.receipt_body.is_empty()
        {
            return Err(refused());
        }
        let held = self.hold.physical_gate_data()?;
        if prospective_release && !held {
            return Err(refused());
        }
        let request = flight.request.as_ref().ok_or_else(refused)?;
        let target = &request.prepare.restoration;
        let gate = flight.gate_data.as_ref().ok_or_else(refused)?;
        gate.validate_data()?;
        let record = PacketNativeRestoredRecord {
            schema: PACKET_NATIVE_RESTORED_RECORD_FEATURE.into(),
            native_receipt,
            captured_owner_state: target.owner_state.clone(),
            captured_journal: target.journal.clone(),
            mapping: target.mapping.clone(),
            restore_commit: gate.restore_commit.clone(),
            restore_response: flight
                .completed_response
                .as_ref()
                .ok_or_else(refused)?
                .clone(),
            context_digest: Bytes::new(gate.context_digest.as_slice().to_vec()),
            physical_gate_held: held && !prospective_release,
        };
        record.validate_data()?;
        Ok(record)
    }
}

impl VerifiedCompleteRestorationHeld {
    pub(crate) fn authenticate_current<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        // The installed SDK sidecar still owns the original private token and
        // same sealed mapping. Its current check includes the actual actor,
        // registration, immutable policy and retained incoming Commit literal.
        connection.authenticate_installed_complete_restoration(&self.mapping)?;
        self.hold.authenticate_held()?;
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        flight.ensure_origin()?;
        if owner
            .restoration
            .as_ref()
            .is_none_or(|attempt| !Rc::ptr_eq(attempt, &self.attempt))
            || !flight.verified
            || !flight.installation_started
            || flight.original.as_ref() != Some(original)
            || !Rc::ptr_eq(&flight.mapping, &self.mapping)
            || flight
                .physical_hold
                .as_ref()
                .is_none_or(|hold| !Rc::ptr_eq(hold, &self.hold))
            || flight.gate_evidence.is_none()
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(crate) fn original_gate_evidence<'a, S: ProviderStream>(
        &'a self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<std::cell::Ref<'a, (ContentRef, Vec<u8>)>, ProviderError> {
        self.authenticate_current(connection, original)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        std::cell::Ref::filter_map(flight, |flight| flight.gate_evidence.as_ref())
            .map_err(|_| refused())
    }

    pub(crate) fn original_result_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
    ) -> Result<PrepareRestoreResult, ProviderError> {
        self.authenticate_current(connection, original)?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        let request = flight.request.as_ref().ok_or_else(refused)?;
        let target = &request.prepare.restoration;
        let launch = flight.launch.as_ref().ok_or_else(refused)?;
        let result = PrepareRestoreResult {
            transaction_id: request.prepare.transaction_id.clone(),
            prepared_token: launch.selection.prepared_token.clone(),
            world_binding_hash: target.target_world.clone(),
            owner_binding_hash: target.target_owner_binding.clone(),
            staged_owner_ids: std::iter::once(target.target_owner.clone()).collect(),
            closed_gate_receipt: flight.gate_evidence.as_ref().ok_or_else(refused)?.0.clone(),
            validated_manifest: target.capture_manifest.clone(),
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) fn retain_completed_control_evidence<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
        control: &mut PacketControl,
    ) -> Result<(), ProviderError> {
        self.authenticate_current(connection, original)?;
        let response = connection.original_complete_restore_commit_response_data(self, original)?;
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        if flight.completed_response.is_some() || !flight.response_body.is_empty() {
            return Err(refused());
        }
        let value = serde_json::to_value(&*response).map_err(ContractError::from)?;
        let extent = crate::connection::serialized_credit(&value, 65_536)?;
        if extent > flight.response_body.capacity() {
            return Err(refused());
        }
        canonical::canonical_json_to_writer(&value, &mut flight.response_body)?;
        if flight.response_body.len() != extent {
            return Err(refused());
        }
        flight.completed_response = Some(canonical::content_ref(
            &flight.response_body,
            "application/json",
        )?);
        drop(flight);
        control.bind_original_restored_evidence(
            &self.hold,
            NativeRestoredControlEvidence {
                boot: Rc::clone(&self.boot),
                attempt: Rc::clone(&self.attempt),
                hold: Rc::clone(&self.hold),
            },
        )
    }

    pub(crate) fn prepare_receipt_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        response: &Envelope,
    ) -> Result<PacketCompleteRestoreCommitReceipt, ProviderError> {
        let expected = {
            let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
            flight.ensure_origin()?;
            let original = flight.original.as_ref().ok_or_else(refused)?;
            self.original_result_data(connection, original)?
        };
        let mut flight = self.attempt.try_borrow_mut().map_err(|_| borrowed())?;
        if flight.receipt_started {
            return Err(refused());
        }
        // The SDK owns the exact response and reserved original slot already.
        // A failed check or unwinding signer consumes this one signing attempt.
        flight.receipt_started = true;

        if !response.extensions.is_empty()
            || response.body.len() != 4
            || response
                .body
                .get("status")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            || response
                .body
                .get("operation_state")
                .and_then(serde_json::Value::as_str)
                != Some("completed")
            || response
                .body
                .get("extensions")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|extensions| !extensions.is_empty())
        {
            return Err(refused());
        }
        flight.receipt_result = Some(
            PrepareRestoreResult::deserialize(response.body.get("result").ok_or_else(refused)?)
                .map_err(ContractError::from)?,
        );
        if flight.receipt_result.as_ref() != Some(&expected) {
            return Err(refused());
        }
        let maximum = usize::try_from(
            flight
                .launch
                .as_ref()
                .ok_or_else(refused)?
                .limits
                .frame_bytes
                .get(),
        )
        .map_err(|_| refused())?;
        let original = flight.original.as_ref().ok_or_else(refused)?;
        connection.authenticate_original_assigned_restore_response(
            original,
            response,
            PacketCompleteRestoreTransferPhase::Commit,
        )?;
        let assigned = complete_restore_transfer_assigned_response_digest(
            original,
            response,
            PacketCompleteRestoreTransferPhase::Commit,
            maximum,
        )?;
        let boot = self.boot.try_borrow().map_err(|_| borrowed())?;
        boot.ensure_origin()?;
        let key: &[u8; 32] = boot
            .data
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| refused())?;
        let receipt = complete_restore_commit_receipt_data(
            key,
            flight.request.as_ref().ok_or_else(refused)?,
            flight.context.as_ref().ok_or_else(refused)?,
            response.sequence,
            &assigned,
        )?;
        let value = serde_json::to_value(&receipt).map_err(ContractError::from)?;
        let extent = crate::connection::serialized_credit(
            &value,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES,
        )?;
        if !flight.receipt_body.is_empty() || extent > flight.receipt_body.capacity() {
            return Err(refused());
        }
        canonical::canonical_json_to_writer(&value, &mut flight.receipt_body)?;
        if flight.receipt_body.len() != extent {
            return Err(refused());
        }
        boot.ensure_origin()?;
        Ok(receipt)
    }
}

impl NativeRestoredControlEvidence {
    /// Authenticates its same released owners without allocating or decoding.
    ///
    /// # Errors
    /// Refuses foreign boot/mapping/hold, incomplete Commit or a held gate.
    pub(crate) fn authenticate_released_custody_data(
        &self,
        boot: &Rc<RefCell<NativeAckBoot>>,
        mapping: &Rc<RefCell<PreparedArchivedNativeProtocolMapping>>,
        hold: &Rc<PacketCompleteRestorePhysicalHold>,
    ) -> Result<(), ProviderError> {
        if !Rc::ptr_eq(boot, &self.boot)
            || !Rc::ptr_eq(hold, &self.hold)
            || self.hold.physical_gate_data()?
        {
            return Err(refused());
        }
        let owner = self.boot.try_borrow().map_err(|_| borrowed())?;
        let flight = self.attempt.try_borrow().map_err(|_| borrowed())?;
        owner.ensure_origin()?;
        flight.ensure_origin()?;
        if owner
            .restoration
            .as_ref()
            .is_none_or(|actual| !Rc::ptr_eq(actual, &self.attempt))
            || flight
                .physical_hold
                .as_ref()
                .is_none_or(|actual| !Rc::ptr_eq(actual, &self.hold))
            || !Rc::ptr_eq(mapping, &flight.mapping)
            || !flight.verified
            || !flight.installation_started
            || !flight.receipt_started
            || flight.completed_response.is_none()
            || flight.response_body.is_empty()
            || flight.receipt_body.is_empty()
        {
            return Err(refused());
        }
        Ok(())
    }
}

#[path = "restore_held/settled.rs"]
mod settled;
