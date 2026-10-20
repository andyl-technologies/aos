//! Authenticates the immutable Create Apply and following Inventory once.
//!
//! Host and metadata recovery borrow the same retained historical packet
//! engine. Historical companion coordinates permit parsing only; current
//! authority always belongs to each enclosing genuine native purpose.

use std::error::Error;
use sha2::{Digest as _, Sha256};

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
        StoredBrokerSessionHistoryV1, canonical_protocol_key_v1},
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

#[derive(Clone, Copy)]
enum HistoricalCreateSelectionV2 {
    RecoverTail,
    HostOriginalPair,
}

fn historical_inventory_index_v2(
    selection: HistoricalCreateSelectionV2,
    apply_terminal_index: usize,
    record_count: usize,
) -> Result<usize, JournalError> {
    let inventory = apply_terminal_index.checked_add(2)
        .ok_or(JournalError::ProtectedBoundary)?;
    if inventory >= record_count
        || matches!(selection, HistoricalCreateSelectionV2::RecoverTail)
            && inventory.checked_add(1) != Some(record_count)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(inventory)
}

#[derive(Clone, Copy)]
struct HistoricalStorageNativeCutV2 {
    names: crate::journal::ProtectedJournalNamesV1,
    next: u64,
    end: u64,
    traffic_digest: [u8; 32],
}

// Only the completed historical owner lends these already-verified models.
// The same-native comparison is repeated against the actual supplied readback;
// none of the borrowed DATA constructs a Reader or current native original.
pub(crate) struct HistoricalStorageHistoryBorrowV2<'held> {
    pub(crate) history: &'held BrokerSessionDurableHistoryV1,
    pub(crate) transcript: &'held VerifiedBrokerSessionTranscriptV1,
    pub(crate) checkpoint: &'held aos_sandbox_protocol::authenticated_session::
        historical_checkpoint::HistoricalSessionCheckpointV1,
}

pub(crate) struct HistoricalCreateSessionOriginalV1 {
    native_cut: Option<HistoricalStorageNativeCutV2>,
    ordinary: StoredBrokerSessionHistoryDecodeCaptureV1,
    verified: Option<Result<VerifiedHistoryV1, Cause>>,
    apply: HistoricalStorageMethodCaptureV1,
    inventory: HistoricalStorageMethodCaptureV1,
    roster: Option<Result<(), Cause>>,
    decode: Option<Result<(), Cause>>,
    capture: Option<Result<(), Cause>>,
    reentered: bool,
}

impl HistoricalCreateSessionOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            native_cut: None,
            ordinary: Default::default(), verified: None,
            apply: HistoricalStorageMethodCaptureV1::new(),
            inventory: HistoricalStorageMethodCaptureV1::new(),
            roster: None, decode: None, capture: None, reentered: false,
        }
    }

    pub(crate) fn decoding_receiving_demand_v1(prefix: usize) -> Result<ResourceVector, JournalError> {
        use aos_sandbox_protocol::authenticated_session::all_methods::request_capture::
            AuthenticatedBrokerMethodRequestCaptureV1;
        let one = RootCurrentStorageInventoryV1::additional_demand_v1(prefix)?;
        let frames = std::mem::size_of::<HistoricalCreateSelectionV2>()
            .checked_add(std::mem::size_of::<usize>().checked_mul(2)
                .ok_or(JournalError::JournalTooLarge)?)
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HistoricalStorageNativeCutV2>().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<HistoricalStorageHistoryBorrowV2<'_>>().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let workspace = AuthenticatedBrokerMethodRequestCaptureV1::
            storage_apply_additional_receiving_demand_v1(prefix)
            .ok_or(JournalError::JournalTooLarge)?;
        one.checked_add(one).and_then(|demand| demand.checked_add(workspace))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, frames)))
            .map_err(JournalError::ReceivingAccounting)
    }

    /// Verifies Host's actual complete current slot before historical parsing.
    pub(crate) fn observe_host_once_v2(&mut self, native: RootFixedNativeReadbackV1<'_>,
        manifest: &BrokerSessionManifestV1, node: [u8; 16], boot: [u8; 16])
        -> Result<(), JournalError>
    {
        if self.roster.is_some() || self.decode.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.roster = Some(verify_storage_history_roster_v2(native.state, manifest, node, boot));
        if !matches!(self.roster, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        self.decode_once_v1(&native)?;
        self.verify_history_once_v1(manifest, node, boot)?;
        self.capture_selected_methods_once_v2(HistoricalCreateSelectionV2::HostOriginalPair)
    }

    pub(crate) fn decode_once_v1(&mut self, native: &RootFixedNativeReadbackV1<'_>) -> Result<(), JournalError> {
        if self.decode.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.decode = Some((|| -> Result<(), Cause> {
            let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage);
            let bytes = native.state.get(&(RecordNamespace::BrokerSessionTraffic, key.clone()))
                .ok_or(JournalError::ProtectedBoundary)?;
            self.native_cut = Some(HistoricalStorageNativeCutV2 {
                names: native.names,
                next: native.next,
                end: native.end,
                traffic_digest: Sha256::digest(bytes).into(),
            });
            StoredBrokerSessionHistoryV1::decode_retaining(&key, bytes, &mut self.ordinary)?;
            Ok(())
        })());
        if matches!(self.decode, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn verify_history_once_v1(&mut self, manifest: &BrokerSessionManifestV1,
        node: [u8; 16], boot: [u8; 16]) -> Result<(), JournalError> {
        if self.verified.is_some() || !matches!(self.decode, Some(Ok(()))) {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.verified = Some((|| {
            let ordinary = self.ordinary.stored().ok_or(JournalError::ProtectedBoundary)?;
            verify_history_v1(manifest, ordinary, node, boot, RootHistoricalSessionPurposeV1::Apply)
        })());
        value(&self.verified).map(|_| ())
    }

    pub(crate) fn capture_methods_once_v1(&mut self) -> Result<(), JournalError> {
        self.capture_selected_methods_once_v2(HistoricalCreateSelectionV2::RecoverTail)
    }

    fn capture_selected_methods_once_v2(&mut self, selection: HistoricalCreateSelectionV2)
        -> Result<(), JournalError>
    {
        if self.capture.is_some() {
            self.reentered = true;
            return Err(JournalError::ProtectedBoundary);
        }
        self.capture = Some(self.capture_methods_inner_v1(selection));
        self.require_complete_v1()
    }

    fn capture_methods_inner_v1(&mut self, selection: HistoricalCreateSelectionV2) -> Result<(), Cause> {
        let ordinary = self.ordinary.stored().ok_or(JournalError::ProtectedBoundary)?;
        let (_, transcript, history, _) = value(&self.verified)?;
        let mut applies = history.records().iter().enumerate().filter(|(_, record)|
            record.phase() == BrokerSessionDurablePhaseV1::Terminal
                && record.method() == BrokerMethod::BROKER_METHOD_STORAGE_APPLY);
        let (index, _) = applies.next().ok_or(JournalError::ProtectedBoundary)?;
        if applies.next().is_some() || index == 0
            || matches!(selection, HistoricalCreateSelectionV2::RecoverTail)
                && index.checked_add(3) != Some(history.records().len())
            || history.records()[..index - 1].iter().any(|record|
                record.method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let inventory = historical_inventory_index_v2(selection, index, history.records().len())?;
        if matches!(selection, HistoricalCreateSelectionV2::HostOriginalPair)
            && history.records()[inventory].method() != BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let checkpoint = ordinary.checkpoint.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.apply.observe_once_v1(history.records(), index, checkpoint, transcript)?;
        self.inventory.observe_once_v1(history.records(), inventory, checkpoint, transcript)?;

        Ok(())
    }

    pub(crate) fn verified_history_for_native_v2(
        &self,
        native: &RootFixedNativeReadbackV1<'_>,
    ) -> Result<HistoricalStorageHistoryBorrowV2<'_>, JournalError> {
        self.require_complete_v1()?;
        let cut = self.native_cut.ok_or(JournalError::ProtectedBoundary)?;
        let key = canonical_protocol_key_v1(BrokerSessionProtocolV1::Storage);
        let bytes = native.state.iter()
            .find(|((namespace, row_key), _)| *namespace == RecordNamespace::BrokerSessionTraffic
                && row_key == &key)
            .map(|(_, bytes)| bytes).ok_or(JournalError::ProtectedBoundary)?;
        if native.names != cut.names || native.next != cut.next || native.end != cut.end
            || <[u8; 32]>::from(Sha256::digest(bytes)) != cut.traffic_digest
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let (_, transcript, history, _) = value(&self.verified)?;
        let checkpoint = self.ordinary.stored()
            .and_then(|stored| stored.checkpoint.as_ref()).ok_or(JournalError::ProtectedBoundary)?;
        Ok(HistoricalStorageHistoryBorrowV2 { history, transcript, checkpoint })
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), JournalError> {
        if !self.reentered && matches!(self.capture, Some(Ok(()))) && self.failure().is_none() { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    pub(crate) fn apply_v1(&self) -> Result<&AuthenticatedBrokerMethodOutcomeV1, JournalError> {
        self.require_complete_v1()?;
        self.apply.outcome_v1().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn apply_response_v1(&self)
        -> Result<&aos_proto::aos::sandbox::local::v1::StorageResult, JournalError> {
        self.require_complete_v1()?;
        self.apply.storage_apply_v1().ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn inventory_v1(&self)
        -> Result<(&AuthenticatedBrokerMethodOutcomeV1, &ValidatedStorageInventory), JournalError> {
        self.require_complete_v1()?;
        Ok((self.inventory.outcome_v1().ok_or(JournalError::ProtectedBoundary)?,
            &self.inventory.inventory_v1().ok_or(JournalError::ProtectedBoundary)?.0))
    }

    /// Borrows the exact authenticated historical plan as comparison DATA.
    pub(crate) fn admitted_plan_v1(&self) -> Result<&[u8], JournalError> {
        self.require_complete_v1()?;
        self.apply.request_v1().and_then(|request| request.authorization())
            .map(|authorization| authorization.broker_plan())
            .ok_or(JournalError::ProtectedBoundary)
    }

    pub(crate) fn require_plan_association_v1(&self,
        publication: &crate::publication::CurrentAuthorityPublicationV1,
    ) -> Result<(), JournalError> {
        self.require_complete_v1()?;
        let [template] = publication.templates() else { return Err(JournalError::ProtectedBoundary); };
        let request = self.apply.request_v1().ok_or(JournalError::ProtectedBoundary)?;
        let authorization = request.authorization().ok_or(JournalError::ProtectedBoundary)?;
        if template.method() != BrokerMethod::BROKER_METHOD_STORAGE_APPLY
            || authorization.broker_plan() != template.canonical_plan()
            || authorization.broker_plan_signature() != template.canonical_plan_signature()
            || authorization.ownership_lease() != publication.lease().canonical_lease()
            || authorization.ownership_lease_signature() != publication.lease().canonical_signature() {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    pub(crate) fn decode_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.ordinary.failure().map(|cause| cause as _)
            .or_else(|| self.decode.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }

    pub(crate) fn verification_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.verified.as_ref()?.as_ref().err().map(|cause| cause.as_ref())
    }

    pub(crate) fn method_failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.apply.failure_v1()
            .or_else(|| self.inventory.failure_v1())
            .or_else(|| self.capture.as_ref()?.as_ref().err().map(|cause| cause.as_ref()))
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.roster.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause.as_ref())
            .or_else(|| self.decode_failure_v1())
            .or_else(|| self.verification_failure_v1())
            .or_else(|| self.method_failure_v1())
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }

}

pub(super) fn verify_history_v1(manifest: &BrokerSessionManifestV1, stored: &StoredBrokerSessionHistoryV1,
    node: [u8; 16], boot: [u8; 16], purpose: RootHistoricalSessionPurposeV1,
) -> Result<VerifiedHistoryV1, Cause> {
    let checkpoint = stored.checkpoint.as_ref().ok_or(JournalError::ProtectedBoundary)?;
    let history = stored.history_model()?;
    let head = history.head()?;
    verify_session_for_purpose_v1(manifest, stored, checkpoint.client_hello_bytes(),
        checkpoint.broker_hello_bytes(), node, boot, head.method(), head.request_packet(),
        head.outcome_packet().ok_or(JournalError::ProtectedBoundary)?, purpose)
}

fn value<T>(value: &Option<Result<T, Cause>>) -> Result<&T, JournalError> {
    value.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

const CLOSED: JournalError = JournalError::ProtectedBoundary;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_keeps_original_inventory_after_later_guest_root_and_inventory() {
        // Terminal indices in the authenticated ordinary history: initial
        // Inventory1, Apply3, Create Inventory5, guest-root7, later Inventory9.
        // This scalar fixture supplies no transcript/native/packet authority.
        assert_eq!(historical_inventory_index_v2(
            HistoricalCreateSelectionV2::HostOriginalPair, 3, 10).unwrap(), 5);
        assert!(historical_inventory_index_v2(
            HistoricalCreateSelectionV2::RecoverTail, 3, 10).is_err());
        assert_eq!(historical_inventory_index_v2(
            HistoricalCreateSelectionV2::RecoverTail, 3, 6).unwrap(), 5);
    }

    #[test]
    fn truncated_or_overflowed_original_pair_remains_closed() {
        for selection in [HistoricalCreateSelectionV2::RecoverTail,
            HistoricalCreateSelectionV2::HostOriginalPair] {
            assert!(historical_inventory_index_v2(selection, 3, 5).is_err());
            assert!(historical_inventory_index_v2(selection, usize::MAX, usize::MAX).is_err());
        }
    }
}
