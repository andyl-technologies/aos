//! Bounded Host preflight for an exact Storage output row.
//!
//! The Host checks its completed reserve, queries Storage, and persists the
//! exchange for historical recovery. This path has no Create or Observe effect.

use aos_sandbox::controller_execution_preissue::ControllerExecutionReserveSourceV1;
use aos_sandbox::runtime_execution::DormantRuntimeExecutionClaimV1;
use aos_sandbox_broker::BrokerEffectStatusV1;

use super::{
    HostBroker, HostCatalog, HostExecutionGrantRequestV1, HostExecutionGrantReservationV1,
};
use crate::state::HostStateStore;
use crate::storage_existing_output::{
    ExistingOutputObservationV1, ExpectedExistingOutputV1, StorageExistingOutputClientV1,
};
use crate::worker::HostWorker;
use crate::{HostError, Result};

impl<C, S, W> HostBroker<C, S, W>
where
    C: HostCatalog,
    S: HostStateStore,
    W: HostWorker,
{
    /// Queries the exact Storage output row after a completed Host reserve and
    /// durably retains the authenticated exchange as a nonauthorizing precursor.
    ///
    /// The expected v2 claim must come from a future authenticated Controller
    /// cut. This method compares its shape and bytes but cannot prove that
    /// provenance, physical backing, or an ordered all-owner handoff. No Host
    /// Apply or Observe effect consumes the retained observation.
    ///
    /// # Errors
    ///
    /// Rejects a missing, superseded, or incomplete Host reserve, stale
    /// protected runtime, mismatched Storage row, or uncertain Host commit.
    pub fn observe_existing_storage_output(
        &mut self,
        reservation: &HostExecutionGrantReservationV1,
        claim: &DormantRuntimeExecutionClaimV1<'_>,
        storage: &StorageExistingOutputClientV1,
        expected: ExpectedExistingOutputV1,
        protected_boot_id: [u8; 16],
    ) -> Result<ExistingOutputObservationV1> {
        if !self.state_healthy {
            let recovered = self.store.load()?;
            recovered.validate_authenticated(&self.authority)?;
            self.state = recovered;
            self.state_healthy = true;
        }
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime claim is stale"))?;
        if claim.host_verifier().boot_id() != protected_boot_id
            || !self.state.execution_handoff_is_current(
                reservation.assignment.sandbox().as_bytes(),
                &reservation.request_id,
            )
            || !super::execution_assignment(claim)
                .is_ok_and(|assignment| assignment == reservation.assignment)
            || claim.currentness().runtime().handle() != reservation.runtime_handle
        {
            return Err(HostError::Fence("Host output reserve is not current"));
        }
        let HostExecutionGrantRequestV1::ReserveOutput(reserve) = &reservation.request else {
            return Err(HostError::Fence("Host request is not an output reserve"));
        };
        if reservation.verified_output_source.is_none() {
            return Err(HostError::Fence("Host output source was not verified"));
        }
        let source = ControllerExecutionReserveSourceV1::decode_structural(reserve.source())
            .map_err(|_| HostError::Fence("Host output source changed"))?;
        if source.preissue().host_boot_id() != protected_boot_id {
            return Err(HostError::Fence("Host output source boot changed"));
        }
        let current_effect = self
            .state
            .effect(&reservation.request_id)
            .ok_or(HostError::Fence("Host output reserve is absent"))?;
        let current_effect = self
            .authority
            .open_effect(&reservation.request_id, current_effect)?;
        if current_effect.status() != BrokerEffectStatusV1::Complete
            || current_effect.transport_request_digest() != reservation.request_body_digest
            || current_effect.request_digest() != reservation.effect.request_digest()
        {
            return Err(HostError::Fence("Host output reserve is not complete"));
        }

        let observation = storage.query_expected(
            *source.preissue().execution().as_bytes(),
            *source.preissue().create_operation().as_bytes(),
            *reservation.assignment.digest().as_bytes(),
            expected,
        )?;
        let response = observation.response();
        if response.maximum_stdout_bytes != source.preissue().maximum_stdout_bytes()
            || response.maximum_stderr_bytes != source.preissue().maximum_stderr_bytes()
        {
            return Err(HostError::Fence(
                "Storage output split differs from Host source",
            ));
        }
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime changed after Storage query"))?;
        if !self.state.execution_handoff_is_current(
            reservation.assignment.sandbox().as_bytes(),
            &reservation.request_id,
        ) {
            return Err(HostError::Fence("Host output reserve was superseded"));
        }
        let mut proposed = self.state.clone();
        proposed.retain_existing_output_observation(
            reservation.request_id,
            protected_boot_id,
            observation,
            &self.authority,
        )?;
        if proposed != self.state {
            self.commit_state(&proposed)?;
        }
        claim
            .revalidate()
            .map_err(|_| HostError::Fence("protected runtime changed after Host commit"))?;
        Ok(observation)
    }

    /// Replays Host's authenticated historical Storage exchange after recovery.
    ///
    /// This does not query Storage or establish currentness. A later owner cut
    /// must obtain fresh evidence before any effect can be considered.
    ///
    /// # Errors
    ///
    /// Rejects corrupt, unauthenticated, or ambiguous Host state.
    pub fn replay_existing_storage_output_observation(
        &mut self,
        host_request_id: [u8; 16],
    ) -> Result<Option<ExistingOutputObservationV1>> {
        if !self.state_healthy {
            let recovered = self.store.load()?;
            recovered.validate_authenticated(&self.authority)?;
            self.state = recovered;
            self.state_healthy = true;
        }
        self.state
            .replay_existing_output_observation(host_request_id, &self.authority)
    }
}
