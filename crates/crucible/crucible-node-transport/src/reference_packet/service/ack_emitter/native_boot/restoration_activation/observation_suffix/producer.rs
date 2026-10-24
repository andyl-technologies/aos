//! Authenticates immutable first-release ancestry for separately spent Producer work.

use super::*;
use crate::reference_packet::control::ReleasedWorldControlInputsData;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

impl OriginalRestoredSuffixPostObservation {
    pub(crate) fn retain_original_producer_ingress_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        records: &[ExchangeRecord],
        frame: usize,
    ) -> Result<
        super::super::super::super::super::restored_suffix::OriginalRestoredProducerRead<'_>,
        ProviderError,
    > {
        self.authenticate_current_data(connection, control, records)?;
        control.authenticate_original_restored_producer_model_data()?;
        let owner = self.released.boot.try_borrow().map_err(|_| borrowed())?;
        let state = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?;
        if usize::try_from(state.original_frame_bytes_data()?).map_err(|_| exhausted())? != frame {
            return Err(refused());
        }
        drop(owner);
        super::super::super::super::super::restored_suffix::OriginalRestoredProducerRead::retain_data(self, &self.released.boot, frame)
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_producer_original_identity_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        let first = self.attempt.try_borrow().map_err(|_| borrowed())?;
        let admitted = first.original.as_ref().ok_or_else(refused)?;
        if original.request_id.0.is_none()
            || original.request_id == admitted.request_id
            || original.sequence <= admitted.sequence
            || original.session_id != admitted.session_id
            || original.incarnation_id != admitted.incarnation_id
            || original.node_id != admitted.node_id
            || original.execution_owner_id != admitted.execution_owner_id
            || original.capture_owner_id.0.is_some()
            || !original.extensions.is_empty()
        {
            return Err(refused());
        }
        if matches!(
            original.method,
            crate::envelope::Method::Begin | crate::envelope::Method::Observe
        ) && (original.body.get("binding_hash") != admitted.body.get("binding_hash")
            || original.body.get("owner_generation") != admitted.body.get("owner_generation"))
        {
            return Err(refused());
        }
        Ok(())
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn producer_activation_boundary_data(
        &self,
    ) -> Result<crucible_node_format::Position, ProviderError> {
        let owner = self.released.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let commit = self.released.commit.try_borrow().map_err(|_| borrowed())?;
        commit.ensure_origin()?;
        if !commit.verified
            || !commit.installation_started
            || !commit.receipt_started
            || self.released.hold.physical_gate_data()?
        {
            return Err(refused());
        }
        Ok(commit
            .request
            .as_ref()
            .ok_or_else(refused)?
            .prepare
            .restoration
            .archived_cut)
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn producer_row_data<
        S: ProviderStream,
    >(
        &self,
        connection: &Connection<S>,
        control: &PacketControl,
        original: &Envelope,
    ) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
        connection
            .original_native_owned11_admission()?
            .authenticate_current(connection)?;
        let owner = self.released.boot.try_borrow().map_err(|_| borrowed())?;
        let state = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?;
        let maximum = state.model_quote_maximum_data()?;
        let commit = self.released.commit.try_borrow().map_err(|_| borrowed())?;
        let launch = commit.launch.as_ref().ok_or_else(refused)?;
        let finish_extent = if original.method == crate::envelope::Method::BlobFinish {
            let transfer = original
                .body
                .get("transfer_id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(refused)?;
            state.published_producer_upload_extent_data(transfer)?
        } else {
            0
        };
        control.original_restored_producer_action_row_data(launch, original, finish_extent, maximum)
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_producer_control_data(
        &self,
        original: &Envelope,
        selection: &crate::reference_packet::control::PacketControlSelection,
        control: &PacketControl,
    ) -> Result<(), ProviderError> {
        self.released
            .policy
            .authenticate_original_control_selection(selection)?;
        self.authenticate_producer_original_identity_data(original)?;
        control.authenticate_original_restored_producer_model_data()?;
        let owner = self.released.boot.try_borrow().map_err(|_| borrowed())?;
        owner.authenticate_original_invocation_prepare_target_data()?;
        let state = owner
            .startup
            .as_ref()
            .and_then(|startup| startup.restored_suffix.as_ref())
            .ok_or_else(refused)?;
        state.authenticate_observation_data(&self.attempt, self.record)?;
        let first = self.attempt.try_borrow().map_err(|_| borrowed())?;
        first.authenticate_published_suffix_milestones_data()?;
        let world = self.released.world.try_borrow().map_err(|_| borrowed())?;
        let commit = self.released.commit.try_borrow().map_err(|_| borrowed())?;
        let scope = &first.artifact.as_ref().ok_or_else(refused)?.request.scope;
        if scope != &world.artifact.as_ref().ok_or_else(refused)?.request.scope {
            return Err(refused());
        }
        control.authenticate_original_restoration_released_control_data(
            ReleasedWorldControlInputsData {
                original: world.original.as_ref().ok_or_else(refused)?,
                terminal: world.terminal.as_ref().ok_or_else(refused)?,
                scope,
                boot: &self.released.boot,
                mapping: &commit.mapping,
                hold: &self.released.hold,
                policy: &self.released.policy,
            },
        )
    }
}
