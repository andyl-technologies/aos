//! Derives only Root query DATA from the same actual authorized Recover loan.
//!
//! The completed native Inventory identity is rejoined to its actual signed
//! outcome and held Session. No receipt, packet digest or decoded row can adopt
//! a Session or construct a completion lender through this projection.

use super::*;
use crate::journal::{JournalError, RecordNamespace};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    KeyV1, OwnerV1, PhaseV1, RecordEnvelopeV1, controller_intent::ControllerIntentBodyDataV1,
};
use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::{
    FinalityRecoverQueryDataV1, finality_admission_commitment_v1, finality_inventory_commitment_v1,
};

impl OperatorCreateRecoveryLoanV1<'_, '_> {
    pub(crate) fn require_root_controller_v1(
        &self,
        controller: &Journal,
    ) -> Result<(), ResourceReservationErrorV1> {
        if !std::ptr::eq(self.controller, controller) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.require_current_v1()
    }

    pub(crate) fn reached_receiving_demand_v1(&self) -> ResourceVector {
        self.owner.reached
    }

    /// Derives fixed comparison DATA from actual entered and completed owners.
    ///
    /// The caller must separately pay the Root connection/peer/stream owner
    /// before using this result. Only its complete strict response and native
    /// posts can admit metadata CAS; this method grants neither IO nor success.
    ///
    /// # Errors
    /// Refuses changed original custody, incomplete Source/Inventory, a foreign
    /// authenticated request or held Session, malformed history or expiry.
    #[doc(hidden)]
    pub fn root_finality_query_data_v1(
        &mut self,
        session: &Journal,
        outcome: &AuthenticatedBrokerMethodOutcomeV1,
    ) -> Result<FinalityRecoverQueryDataV1, ResourceReservationErrorV1> {
        self.require_current_v1()?;
        self.check_frontier_v1()?;
        let (nonce, binding) = self
            .owner
            .storage
            .require_root_inventory_data_v1(session, outcome)?;
        self.owner.source.require_observed_for_root_v1()?;
        let admission = self.owner.current_observation_data_v1(self.controller)?;
        let key = admission.key_v1();
        let raw = self
            .controller
            .get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let query = FinalityRecoverQueryDataV1 {
            nonce,
            admission_key: key,
            admission: finality_admission_commitment_v1(raw),
            lane: lane_v1(
                self.controller,
                aos_sandbox_model::OperationId::from_bytes(admission.target),
            )?,
            inventory: finality_inventory_commitment_v1(outcome.canonical_packet()),
            inventory_session: binding,
            original: admission.original,
            cutoff: admission.cutoff,
            wall_expiry: admission.wall_expiry,
        };
        query
            .encode_v1()
            .map_err(|_| ResourceReservationErrorV1::Conflict)?;
        Ok(query)
    }
}

// The whole C has already passed its actual native/full-family audit. This
// allocation-free selector uses only the existing canonical key/envelope/body
// decoders and refuses duplicate operation-to-lane associations.
fn lane_v1(
    controller: &Journal,
    parent: aos_sandbox_model::OperationId,
) -> Result<[u8; 16], ResourceReservationErrorV1> {
    let mut selected = None;
    for (key, bytes) in controller.records(RecordNamespace::CreateStorageHistory) {
        let key = KeyV1::decode(key).map_err(|_| JournalError::ProtectedBoundary)?;
        if key.owner() != OwnerV1::Controller || key.revision() != 1 {
            continue;
        }
        let record = RecordEnvelopeV1::decode(
            bytes,
            key,
            PhaseV1::new(OwnerV1::Controller, 1).map_err(|_| JournalError::ProtectedBoundary)?,
        )
        .map_err(|_| JournalError::ProtectedBoundary)?;
        let intent = ControllerIntentBodyDataV1::decode(record.body())
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if intent.identity.operation == *parent.as_bytes() {
            if selected.replace(key.lane()).is_some() {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
    }
    selected.ok_or(ResourceReservationErrorV1::Conflict)
}
