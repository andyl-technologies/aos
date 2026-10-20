//! Retains historical Apply and distinct newly authorized Inventory18 evidence.
//!
//! Both logical slots come from the same actual fixed protected Session reader.
//! The ordinary Apply head is never retired, overwritten or resumed. Historical
//! packet interpretation uses only each authenticated durable companion's parse
//! coordinate, and cannot turn an expired Apply lease into current authority.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker_session_protocol::{BrokerSessionProtocolV1,
    BrokerSessionDurablePhaseV1, BrokerSessionDurableHistoryV1,
    BrokerSessionTrafficStateV1, ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1};
use aos_sandbox_broker_session_protocol::hello_message::BrokerMethod;
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_protocol::authenticated_session::{
    all_methods::AuthenticatedBrokerMethodOutcomeV1,
    historical_method::HistoricalStorageMethodCaptureV1,
    stored_history::{StoredBrokerSessionHistoryDecodeCaptureV1,
        StoredBrokerSessionHistoryV1,
        canonical_operator_recover_inventory_key_v1},
};
use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::{
    FinalityRecoverQueryDataV1, finality_inventory_commitment_v1,
};
use aos_sandbox_protocol::storage_inventory::ValidatedStorageInventory;

use crate::journal::{JournalError, RecordNamespace};
use crate::policy_compiler::create_storage_current::controller_readonly::{
    native_read::RootFixedNativeReadbackV1,
    storage_inventory::{RootCurrentStorageInventoryV1,
        RootHistoricalSessionPurposeV1, verify_session_for_purpose_v1,
        verify_storage_history_roster_v2},
};

type Cause = Box<dyn Error>;
type VerifiedHistoryV1 = (ProtectedBrokerSessionVerificationContextV1,
    VerifiedBrokerSessionTranscriptV1, BrokerSessionDurableHistoryV1,
    BrokerSessionTrafficStateV1);

/// Retains the three exact signed exchanges used only by metadata finality.
pub(crate) struct CreateFinalitySessionOriginalV1 {
    ordinary: super::super::historical_create_session::HistoricalCreateSessionOriginalV1,
    recover: StoredBrokerSessionHistoryDecodeCaptureV1,
    recover_verified: Option<Result<VerifiedHistoryV1, Cause>>,
    fresh_inventory: HistoricalStorageMethodCaptureV1,
    result: Option<Result<(), Cause>>,
    reentered: bool,
}

impl CreateFinalitySessionOriginalV1 {
    pub(crate) fn new() -> Self {
        Self { ordinary: super::super::historical_create_session::HistoricalCreateSessionOriginalV1::new(), recover: Default::default(),
            recover_verified: None,
            fresh_inventory: HistoricalStorageMethodCaptureV1::new(),
            result: None, reentered: false }
    }

    // Three independent packet/capture planes coexist. The shared supplier
    // covers each actual prefix, canonical body and semantic decoder, while
    // Apply's workspace passes and this exact fixed layout remain additional.
    pub(crate) fn receiving_demand_v1(prefix: usize) -> Result<ResourceVector, JournalError> {
        let history = super::super::historical_create_session::HistoricalCreateSessionOriginalV1::
            decoding_receiving_demand_v1(prefix)?;
        let fresh = RootCurrentStorageInventoryV1::additional_demand_v1(prefix)?;
        let bytes = size_of::<Self>().checked_mul(3)
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        history.checked_add(fresh)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Verifies both complete fixed slots and the exact newly observed signed head.
    pub(crate) fn observe_once_v1(&mut self, native: RootFixedNativeReadbackV1<'_>,
        manifest: &BrokerSessionManifestV1, query: FinalityRecoverQueryDataV1,
        node: [u8; 16], boot: [u8; 16],
    ) -> Result<(), JournalError> {
        if self.result.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.result = Some(self.observe_inner_v1(native, manifest, query, node, boot));
        self.require_complete_v1()
    }

    fn observe_inner_v1(&mut self, native: RootFixedNativeReadbackV1<'_>,
        manifest: &BrokerSessionManifestV1, query: FinalityRecoverQueryDataV1,
        node: [u8; 16], boot: [u8; 16],
    ) -> Result<(), Cause> {
        verify_storage_history_roster_v2(native.state, manifest, node, boot)?;
        let recover_key = canonical_operator_recover_inventory_key_v1();
        self.ordinary.decode_once_v1(&native)?;
        let recover_bytes = native.state.get(&(RecordNamespace::BrokerSessionTraffic, recover_key.clone()))
            .ok_or(JournalError::ProtectedBoundary)?;
        StoredBrokerSessionHistoryV1::decode_retaining(&recover_key, recover_bytes, &mut self.recover)?;
        let recover = self.recover.stored().ok_or(JournalError::ProtectedBoundary)?;
        // Both independent verification Results remain reached in the same
        // original order, even when the historical ordinary verifier refuses.
        let _historical = self.ordinary.verify_history_once_v1(manifest, node, boot);
        self.recover_verified = Some(super::super::historical_create_session::verify_history_v1(
            manifest, recover, node, boot, RootHistoricalSessionPurposeV1::OperatorRecoverInventory));
        self.ordinary.capture_methods_once_v1()?;

        let (_, transcript, history, _) = value(&self.recover_verified)?;
        if transcript.session_binding() != query.inventory_session
            || history.records().len() != 2
            || history.records().iter().any(|record|
                record.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let checkpoint = recover.checkpoint.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.fresh_inventory.observe_once_v1(history.records(), 1, checkpoint, transcript)?;
        let request = self.fresh_inventory.request_v1().ok_or(JournalError::ProtectedBoundary)?;
        let outcome = self.fresh_inventory.outcome_v1().ok_or(JournalError::ProtectedBoundary)?;
        if request.authorization().is_some()
            || request.request_id() != query.nonce
            || request.deadline_boottime_nanoseconds() <= query.original.boottime_nanoseconds()
            || request.deadline_boottime_nanoseconds() > query.cutoff
            || finality_inventory_commitment_v1(outcome.canonical_packet()) != query.inventory
            || self.fresh_inventory.inventory_v1().is_none() {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if !self.reentered && matches!(self.result, Some(Ok(()))) && self.failure().is_none() { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn apply_v1(&self) -> Result<&AuthenticatedBrokerMethodOutcomeV1, JournalError> {
        self.require_complete_v1()?;
        self.ordinary.apply_v1()
    }

    pub(crate) fn apply_response_v1(&self)
        -> Result<&aos_proto::aos::sandbox::local::v1::StorageResult, JournalError> {
        self.require_complete_v1()?;
        self.ordinary.apply_response_v1()
    }

    pub(crate) fn historical_inventory_v1(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ValidatedStorageInventory), JournalError> {
        self.require_complete_v1()?;
        self.ordinary.inventory_v1()
    }

    pub(crate) fn fresh_inventory_v1(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ValidatedStorageInventory), JournalError> {
        self.require_complete_v1()?;
        Ok((self.fresh_inventory.outcome_v1().ok_or(JournalError::ProtectedBoundary)?,
            &self.fresh_inventory.inventory_v1().ok_or(JournalError::ProtectedBoundary)?.0))
    }

    pub(crate) fn require_plan_association_v1(&self,
        publication: &crate::publication::CurrentAuthorityPublicationV1,
    ) -> Result<(), JournalError> {
        self.require_complete_v1()?;
        self.ordinary.require_plan_association_v1(publication)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.ordinary.decode_failure_v1()
            .or_else(|| self.recover.failure().map(|cause| cause as _))
            .or_else(|| self.ordinary.verification_failure_v1())
            .or_else(|| self.recover_verified.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.ordinary.method_failure_v1())
            .or_else(|| self.fresh_inventory.failure_v1())
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

fn value<T>(value: &Option<Result<T, Cause>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;
