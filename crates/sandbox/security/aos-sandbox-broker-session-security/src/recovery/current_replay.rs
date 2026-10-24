//! Retains actual canonical replay values across later Client refusals.
//!
//! Ordinary callers own the same local values and keep their existing drop
//! order. The selected Client lends inert result destinations; each actual
//! returned value is parked before the next fallible operation. This module
//! supplies no Journal, writer, policy authority or resource payer.

use super::*;
use std::ops::Deref;
use super::journal::StoredReadOriginalsV1;
use aos_sandbox_broker_session_protocol::durable::history::BrokerSessionDurableHistoryDecodeCaptureV1;
use aos_sandbox_broker_session_protocol::durable::{
    HistoricalTrafficReplayCaptureV1, verify_historical_traffic_records_retaining_v1,
};

mod storage_receiving;
pub(in crate::recovery) use storage_receiving::StorageSessionReplayArchiveV3;

/// Holds either the ordinary local value or its already-parked selected value.
pub(super) enum ReplayValue<'owner, T> {
    Ordinary(T),
    Retained(&'owner T),
}

impl<T> Deref for ReplayValue<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        match self {
            Self::Ordinary(value) => value,
            Self::Retained(value) => value,
        }
    }
}

impl<T> ReplayValue<'_, T> {
    pub(super) fn into_ordinary(self) -> T {
        match self {
            Self::Ordinary(value) => value,
            Self::Retained(_) => std::process::abort(),
        }
    }
}

pub(super) fn security_value<'owner, T>(
    observed: Result<T, BrokerSessionSecurityError>,
    destination: Option<&'owner mut Option<Result<T, BrokerSessionSecurityError>>>,
) -> Result<ReplayValue<'owner, T>, BrokerSessionSecurityError> {
    let Some(destination) = destination else {
        return observed.map(ReplayValue::Ordinary);
    };
    if destination.is_some() {
        std::process::abort();
    }
    *destination = Some(observed);
    match destination.as_ref() {
        Some(Ok(value)) => Ok(ReplayValue::Retained(value)),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

#[derive(Clone, Copy, Default)]
enum RetainedCurrentPurposeV1 {
    #[default]
    Storage,
    DeleteInventory,
    ReconciliationInventory,
}

fn current_value<'owner>(
    authority: &mut ProtectedBrokerSessionJournalV1,
    protocol: BrokerSessionProtocolV1,
    originals: Option<&'owner mut StoredReadOriginalsV1>,
    purpose: RetainedCurrentPurposeV1,
    receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
) -> Result<ReplayValue<'owner, ProtectedBrokerSessionJournalSnapshotV1>, BrokerSessionSecurityError> {
    let Some(originals) = originals else {
        return match receiving {
            Some(source) => authority.read_current_in_storage_validation_v3(protocol, source),
            None => authority.read_current(protocol),
        }.map(ReplayValue::Ordinary);
    };
    // Selected financial callers use the canonical ordinary result engine.
    // Existing non-Storage destinations retain their unchanged legacy recipe.
    if receiving.is_some() { return Err(BrokerSessionSecurityError::Currentness); }
    match purpose {
        RetainedCurrentPurposeV1::Storage => {
            if protocol != BrokerSessionProtocolV1::Storage {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            originals.observe_current_once(authority)?;
        }
        RetainedCurrentPurposeV1::DeleteInventory | RetainedCurrentPurposeV1::ReconciliationInventory => {
            originals.observe_delete_current_once_v1(authority, protocol)?;
        }
    }
    originals.snapshot().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

pub(super) fn traffic_value<'owner>(
    history: &BrokerSessionDurableHistoryV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    originals: Option<&'owner mut HistoricalTrafficReplayCaptureV1>,
) -> Result<ReplayValue<'owner, BrokerSessionTrafficStateV1>, BrokerSessionSecurityError> {
    let Some(originals) = originals else {
        return reconstruct_traffic(history, transcript, context).map(ReplayValue::Ordinary);
    };
    verify_historical_traffic_records_retaining_v1(history.records(), transcript, context, originals)
        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
    originals.traffic().map(ReplayValue::Retained).ok_or(BrokerSessionSecurityError::Currentness)
}

pub(super) fn head_value<'history>(
    observed: Result<&'history BrokerSessionDurableRecordV1, BrokerSessionDurableError>,
    destination: Option<&mut Option<Result<(), BrokerSessionDurableError>>>,
) -> Result<&'history BrokerSessionDurableRecordV1, BrokerSessionSecurityError> {
    let Some(destination) = destination else {
        return observed.map_err(map_durable);
    };
    if destination.is_some() {
        std::process::abort();
    }
    match observed {
        Ok(head) => {
            *destination = Some(Ok(()));
            Ok(head)
        }
        Err(cause) => {
            *destination = Some(Err(cause));
            Err(BrokerSessionSecurityError::Currentness)
        }
    }
}

#[derive(Default)]
struct DecodedHistoryOriginalsV1 {
    bytes: Option<Result<(), BrokerSessionSecurityError>>,
    history: BrokerSessionDurableHistoryDecodeCaptureV1,
    commitment: Option<Result<(), BrokerSessionSecurityError>>,
}

impl DecodedHistoryOriginalsV1 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        failure(&self.bytes)
            .or_else(|| self.history.failure().map(|cause| cause as _))
            .or_else(|| failure(&self.commitment))
    }
}

fn decode_snapshot_history<'owner>(
    snapshot: &ProtectedBrokerSessionJournalSnapshotV1,
    originals: Option<&'owner mut DecodedHistoryOriginalsV1>,
) -> Result<ReplayValue<'owner, BrokerSessionDurableHistoryV1>, BrokerSessionSecurityError> {
    let (bytes_slot, history_slot, commitment_slot) = match originals {
        Some(originals) => (
            Some(&mut originals.bytes),
            Some(&mut originals.history),
            Some(&mut originals.commitment),
        ),
        None => (None, None, None),
    };
    security_value(
        snapshot.history.as_ref().map(|_| ()).ok_or(BrokerSessionSecurityError::Currentness),
        bytes_slot,
    )?;
    let bytes = match snapshot.history.as_deref() {
        Some(bytes) => bytes,
        None => std::process::abort(),
    };
    let history = match history_slot {
        Some(capture) => {
            BrokerSessionDurableHistoryV1::decode_retaining(bytes, capture).map_err(map_durable)?;
            ReplayValue::Retained(capture.history().ok_or(BrokerSessionSecurityError::Currentness)?)
        }
        None => ReplayValue::Ordinary(BrokerSessionDurableHistoryV1::decode(bytes).map_err(map_durable)?),
    };
    security_value(
        if history.head_commitment() == snapshot.current_head {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::Currentness)
        },
        commitment_slot,
    )?;
    Ok(history)
}

#[derive(Default)]
struct UnchangedOriginalsV1 {
    after: StoredReadOriginalsV1,
    comparison: Option<Result<(), BrokerSessionSecurityError>>,
}

impl UnchangedOriginalsV1 {
    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.after.failure().or_else(|| failure(&self.comparison))
    }
}

fn require_unchanged_engine(
    authority: &mut ProtectedBrokerSessionJournalV1,
    protocol: BrokerSessionProtocolV1,
    before: &ProtectedBrokerSessionJournalSnapshotV1,
    originals: Option<&mut UnchangedOriginalsV1>,
    purpose: RetainedCurrentPurposeV1,
) -> Result<(), BrokerSessionSecurityError> {
    require_unchanged_with_storage_receiving_v3(authority, protocol, before, originals, purpose, None)
}

fn require_unchanged_with_storage_receiving_v3(
    authority: &mut ProtectedBrokerSessionJournalV1,
    protocol: BrokerSessionProtocolV1,
    before: &ProtectedBrokerSessionJournalSnapshotV1,
    originals: Option<&mut UnchangedOriginalsV1>,
    purpose: RetainedCurrentPurposeV1,
    receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
) -> Result<(), BrokerSessionSecurityError> {
    let (after_slot, comparison_slot) = match originals {
        Some(originals) => (Some(&mut originals.after), Some(&mut originals.comparison)),
        None => (None, None),
    };
    let after = current_value(authority, protocol, after_slot, purpose, receiving)?;
    let unchanged = *after == *before;
    // The ordinary comparison's temporary snapshot was disposed before its
    // branch returned. The selected value remains on its original destination.
    drop(after);
    security_value(
        if unchanged { Ok(()) } else { Err(BrokerSessionSecurityError::Currentness) },
        comparison_slot,
    )?;
    Ok(())
}

/// Parks both readbacks, the actual decoded history and complete traffic state.
#[derive(Default)]
pub(super) struct ReopenCurrentOriginalsV1 {
    purpose: RetainedCurrentPurposeV1,
    delete_entry: Option<Result<(), BrokerSessionSecurityError>>,
    session: Option<Result<(), BrokerSessionSecurityError>>,
    before: StoredReadOriginalsV1,
    decoded: DecodedHistoryOriginalsV1,
    head: Option<Result<(), BrokerSessionDurableError>>,
    protected: Option<Result<BrokerSessionProtectedBindingsV1, BrokerSessionSecurityError>>,
    peer: Option<Result<BrokerSessionPeerBindingV1, BrokerSessionSecurityError>>,
    head_comparison: Option<Result<(), BrokerSessionSecurityError>>,
    traffic: HistoricalTrafficReplayCaptureV1,
    unchanged: UnchangedOriginalsV1,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl ReopenCurrentOriginalsV1 {
    // Only the actual D outcome validator calls this after its genuine fixed
    // predecessor entry. The callee repeats that same closed original join;
    // callers cannot choose a protocol, role, payer or raw reader.
    pub(in crate::recovery) fn bind_delete_inventory_once_v1(&mut self,
        journal: &ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.session.is_some() || self.delete_entry.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.delete_entry = Some(journal.require_delete_inventory_predecessor_v1(owner));
        if !matches!(self.delete_entry, Some(Ok(()))) {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.purpose = RetainedCurrentPurposeV1::DeleteInventory;
        Ok(())
    }

    pub(in crate::recovery) fn bind_reconciliation_inventory_once_v2(&mut self,
        journal: &ProtectedBrokerSessionJournalV1,
        owner: &ProtectedBrokerOutcomeCurrentnessOwnerV1,
        method: aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.session.is_some() || self.delete_entry.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.delete_entry = Some(journal.require_reconciliation_inventory_predecessor_v2(owner, method));
        if !matches!(self.delete_entry, Some(Ok(()))) { return Err(BrokerSessionSecurityError::Currentness); }
        self.purpose = RetainedCurrentPurposeV1::ReconciliationInventory;
        Ok(())
    }

    pub(in crate::recovery) fn negotiated_delete_preimages_v2(&self) -> Option<(
        &[u8], &aos_sandbox_protocol::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointV1,
        &BrokerSessionDurableHistoryV1,
    )> {
        if !matches!(self.purpose, RetainedCurrentPurposeV1::DeleteInventory | RetainedCurrentPurposeV1::ReconciliationInventory)
            || !matches!(self.delete_entry, Some(Ok(()))) { return None; }
        let (history, _, snapshot) = self.values()?;
        Some((snapshot.history.as_deref()?, self.before.negotiated_checkpoint_data_v2()?, history))
    }

    /// Observes one canonical replay without disposing earlier reached values.
    ///
    /// # Errors
    /// Retains the exact failed current-read, decode, binding, traffic or
    /// second-read result; repeated entry closes without another observation.
    pub(super) fn observe_once(
        &mut self,
        authority: &mut ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        context: &ProtectedBrokerSessionVerificationContextV1,
        peer: &ObservedBrokerPeerExecutionV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.session.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let returned = match reopen_engine(authority, transcript, context, peer, Some(self)) {
            Ok(values) => {
                drop(values);
                Ok(())
            }
            Err(cause) => Err(cause),
        };
        self.returned = Some(returned);
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::Currentness)
        }
    }

    /// Borrows the same values only after this whole replay returned positive.
    pub(super) fn values(&self) -> Option<(
        &BrokerSessionDurableHistoryV1,
        &BrokerSessionTrafficStateV1,
        &ProtectedBrokerSessionJournalSnapshotV1,
    )> {
        if !matches!(self.returned, Some(Ok(()))) || self.closed.is_some() {
            return None;
        }
        Some((
            self.decoded.history.history()?,
            self.traffic.traffic()?,
            self.before.snapshot()?,
        ))
    }

    /// Borrows the first actual reached failure before its coarse projection.
    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        failure(&self.delete_entry)
            .or_else(|| failure(&self.session))
            .or_else(|| self.before.failure())
            .or_else(|| self.decoded.failure())
            .or_else(|| failure(&self.head))
            .or_else(|| failure(&self.protected))
            .or_else(|| failure(&self.peer))
            .or_else(|| failure(&self.head_comparison))
            .or_else(|| self.traffic.cause())
            .or_else(|| self.unchanged.failure())
            .or_else(|| failure(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Counts coexisting fixed destinations and their active nested capsules.
    pub(super) fn metadata_cells() -> Option<usize> {
        // Session; byte/head comparisons; head/protected/peer; unchanged
        // comparison; returned result and refusal are ten outer cells.
        10_usize.checked_add(StoredReadOriginalsV1::receiving_metadata_cells_v1()?.checked_mul(2)?)?
            .checked_add(BrokerSessionDurableHistoryDecodeCaptureV1::receiving_metadata_cells_v1()?)?
            .checked_add(HistoricalTrafficReplayCaptureV1::receiving_metadata_cells_v1()?)
    }

}

struct ReopenedCurrentV1<'owner> {
    history: ReplayValue<'owner, BrokerSessionDurableHistoryV1>,
    traffic: ReplayValue<'owner, BrokerSessionTrafficStateV1>,
    before: ReplayValue<'owner, ProtectedBrokerSessionJournalSnapshotV1>,
}

fn reopen_engine<'owner>(
    authority: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: &ObservedBrokerPeerExecutionV1,
    originals: Option<&'owner mut ReopenCurrentOriginalsV1>,
) -> Result<ReopenedCurrentV1<'owner>, BrokerSessionSecurityError> {
    reopen_with_storage_receiving_v3(authority, transcript, context, peer, originals, None)
}

fn reopen_with_storage_receiving_v3<'owner>(
    authority: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: &ObservedBrokerPeerExecutionV1,
    originals: Option<&'owner mut ReopenCurrentOriginalsV1>,
    mut receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
) -> Result<ReopenedCurrentV1<'owner>, BrokerSessionSecurityError> {
    let purpose = originals.as_ref().map(|originals| originals.purpose).unwrap_or_default();
    let (session_slot, before_slot, decoded, head_slot, protected_slot, peer_slot,
        head_comparison_slot, traffic_slot, unchanged) = match originals {
        Some(originals) => (
            Some(&mut originals.session), Some(&mut originals.before),
            Some(&mut originals.decoded), Some(&mut originals.head),
            Some(&mut originals.protected), Some(&mut originals.peer),
            Some(&mut originals.head_comparison), Some(&mut originals.traffic),
            Some(&mut originals.unchanged),
        ),
        None => (None, None, None, None, None, None, None, None, None),
    };
    security_value(require_current_session(transcript, context), session_slot)?;
    let before = current_value(authority, transcript.protocol(), before_slot, purpose,
        receiving.as_mut().map(|source| &mut **source as &mut dyn StorageFloorFinancialSourceV2))?;
    let history = decode_snapshot_history(&before, decoded)?;
    let head = head_value(history.head(), head_slot)?;
    let protected_bindings = security_value(before.protected_bindings(context), protected_slot)?;
    let peer_binding = security_value(peer.binding(head.endpoint(), transcript, context), peer_slot)?;
    security_value(
        if head.protocol() != transcript.protocol()
            || head.session_binding() != transcript.session_binding()
            || head.protected_bindings() != *protected_bindings
            || head.peer_binding() != *peer_binding
        {
            Err(BrokerSessionSecurityError::Currentness)
        } else {
            Ok(())
        },
        head_comparison_slot,
    )?;
    let traffic = traffic_value(&history, transcript, context, traffic_slot)?;
    require_unchanged_with_storage_receiving_v3(authority, transcript.protocol(), &before, unchanged, purpose, receiving)?;
    Ok(ReopenedCurrentV1 { history, traffic, before })
}

pub(super) fn reopen_ordinary(
    authority: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: &ObservedBrokerPeerExecutionV1,
) -> Result<(BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionJournalSnapshotV1), BrokerSessionSecurityError> {
    reopen_ordinary_with_storage_receiving_v3(authority, transcript, context, peer, None)
}

pub(super) fn reopen_ordinary_with_storage_receiving_v3(
    authority: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: &ObservedBrokerPeerExecutionV1,
    receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
) -> Result<(BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionJournalSnapshotV1), BrokerSessionSecurityError> {
    if let Some(receiving) = receiving {
        return authority.reopen_current_with_storage_archive_v3(transcript, context, peer, receiving);
    }
    let values = reopen_with_storage_receiving_v3(authority, transcript, context, peer, None, None)?;
    Ok((values.history.into_ordinary(), values.traffic.into_ordinary(), values.before.into_ordinary()))
}

pub(in crate::recovery) fn reopen_prepaid_with_storage_receiving_v3(
    authority: &mut ProtectedBrokerSessionJournalV1,
    transcript: &VerifiedBrokerSessionTranscriptV1,
    context: &ProtectedBrokerSessionVerificationContextV1,
    peer: &ObservedBrokerPeerExecutionV1,
    receiving: &mut dyn StorageFloorFinancialSourceV2,
) -> Result<(BrokerSessionDurableHistoryV1, BrokerSessionTrafficStateV1,
    ProtectedBrokerSessionJournalSnapshotV1), BrokerSessionSecurityError> {
    let values = reopen_with_storage_receiving_v3(authority, transcript, context, peer, None, Some(receiving))?;
    Ok((values.history.into_ordinary(), values.traffic.into_ordinary(), values.before.into_ordinary()))
}

pub(super) fn decode_ordinary(
    snapshot: &ProtectedBrokerSessionJournalSnapshotV1,
) -> Result<BrokerSessionDurableHistoryV1, BrokerSessionSecurityError> {
    decode_snapshot_history(snapshot, None).map(ReplayValue::into_ordinary)
}

pub(super) fn unchanged_ordinary(
    authority: &mut ProtectedBrokerSessionJournalV1,
    protocol: BrokerSessionProtocolV1,
    before: &ProtectedBrokerSessionJournalSnapshotV1,
) -> Result<(), BrokerSessionSecurityError> {
    require_unchanged_engine(authority, protocol, before, None, RetainedCurrentPurposeV1::Storage)
}

pub(super) fn unchanged_ordinary_with_storage_receiving_v3(
    authority: &mut ProtectedBrokerSessionJournalV1,
    protocol: BrokerSessionProtocolV1,
    before: &ProtectedBrokerSessionJournalSnapshotV1,
    receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
) -> Result<(), BrokerSessionSecurityError> {
    require_unchanged_with_storage_receiving_v3(authority, protocol, before, None,
        RetainedCurrentPurposeV1::Storage, receiving)
}

fn failure<T, E: std::error::Error + 'static>(
    result: &Option<Result<T, E>>,
) -> Option<&(dyn std::error::Error + 'static)> {
    result.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
}

pub(super) fn receiving_footprint_v1() -> Option<(usize, usize)> {
    // The retained owner itself is already in the actual terminal sizeof.
    // These extra fixed carriers cover its construction temporary, the engine's
    // three owned-or-borrowed locals, its returned carrier and scalar bindings.
    let bytes = std::mem::size_of::<ReopenCurrentOriginalsV1>()
        .checked_add(std::mem::size_of::<ReopenedCurrentV1<'static>>())?
        .checked_add(std::mem::size_of::<Result<ReopenedCurrentV1<'static>, BrokerSessionSecurityError>>())?
        .checked_add(std::mem::size_of::<ReplayValue<'static, BrokerSessionProtectedBindingsV1>>())?
        .checked_add(std::mem::size_of::<ReplayValue<'static, BrokerSessionPeerBindingV1>>())?
        .checked_add(std::mem::size_of::<RetainedCurrentPurposeV1>().checked_mul(3)?)?;
    let bytes = bytes
        .checked_add(StoredReadOriginalsV1::receiving_fixed_backing_bytes_v1()?.checked_mul(2)?)?
        .checked_add(StoredReadOriginalsV1::construction_bytes_v1()?)?
        .checked_add(std::mem::size_of::<BrokerSessionDurableHistoryDecodeCaptureV1>())?
        .checked_add(std::mem::size_of::<HistoricalTrafficReplayCaptureV1>())?;
    Some((bytes, ReopenCurrentOriginalsV1::metadata_cells()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_decoded_history_survives_its_later_head_mismatch() {
        let mut fixture = journal::LifecycleTerminalFixture::storage_client();
        let protocol = fixture.currentness.as_ref().unwrap().transcript.protocol();
        let mut snapshot = fixture.journal.read_current(protocol).unwrap();
        snapshot.current_head[0] ^= 1;
        let mut originals = DecodedHistoryOriginalsV1::default();

        assert!(decode_snapshot_history(&snapshot, Some(&mut originals)).is_err());

        let actual = originals.history.history().unwrap();
        assert_ne!(actual.head_commitment(), snapshot.current_head);
        assert!(matches!(originals.commitment,
            Some(Err(BrokerSessionSecurityError::Currentness))));
        assert!(originals.failure().unwrap().is::<BrokerSessionSecurityError>());
        assert!(!actual.records().is_empty());
    }

    #[test]
    fn actual_valid_rows_survive_a_later_truncated_record_frame() {
        let mut fixture = journal::LifecycleTerminalFixture::storage_client();
        let mut bytes = fixture.journal.read_current(BrokerSessionProtocolV1::Storage)
            .unwrap().history.unwrap();
        let original = BrokerSessionDurableHistoryV1::decode(&bytes).unwrap();
        let count = u32::try_from(original.records().len()).unwrap();
        bytes[10..14].copy_from_slice(&(count + 1).to_be_bytes());
        // Three bytes cannot complete the next actual record length.
        bytes.extend_from_slice(&[0, 0, 1]);
        let mut capture = BrokerSessionDurableHistoryDecodeCaptureV1::new();

        assert!(BrokerSessionDurableHistoryV1::decode_retaining(&bytes, &mut capture).is_err());

        assert!(capture.history().is_none());
        assert_eq!(capture.retained_records(), original.records());
        assert!(matches!(capture.failure(), Some(BrokerSessionDurableError::InvalidLength)));
        let address = capture.retained_records().as_ptr();
        assert!(BrokerSessionDurableHistoryV1::decode_retaining(&bytes, &mut capture).is_err());
        assert_eq!(capture.retained_records().as_ptr(), address);
    }

    #[test]
    fn actual_complete_rows_survive_the_outer_encoded_head_refusal() {
        let mut fixture = journal::LifecycleTerminalFixture::storage_client();
        let mut bytes = fixture.journal.read_current(BrokerSessionProtocolV1::Storage)
            .unwrap().history.unwrap();
        let original = BrokerSessionDurableHistoryV1::decode(&bytes).unwrap();
        bytes[14] ^= 1;
        let mut capture = BrokerSessionDurableHistoryDecodeCaptureV1::new();

        assert!(BrokerSessionDurableHistoryV1::decode_retaining(&bytes, &mut capture).is_err());

        assert!(capture.history().is_none());
        assert_eq!(capture.retained_records(), original.records());
        assert_eq!(capture.retained_head_encoding().unwrap(), original.head().unwrap().encode().unwrap());
        assert!(matches!(capture.failure(), Some(BrokerSessionDurableError::InvalidFormat)));
    }

    #[test]
    fn actual_record_packet_survives_a_later_unknown_kind_refusal() {
        use aos_sandbox_broker_session_protocol::durable::BrokerSessionDurableRecordDecodeCaptureV1;

        let mut fixture = journal::LifecycleTerminalFixture::storage_client();
        let snapshot = fixture.journal.read_current(BrokerSessionProtocolV1::Storage).unwrap();
        let history = BrokerSessionDurableHistoryV1::decode(snapshot.history.as_deref().unwrap()).unwrap();
        let original = history.head().unwrap();
        let mut bytes = original.encode().unwrap();
        bytes[10] = u8::MAX;
        let mut capture = BrokerSessionDurableRecordDecodeCaptureV1::new();

        let ordinary = BrokerSessionDurableRecordV1::decode(&bytes).unwrap_err();
        let returned = BrokerSessionDurableRecordV1::decode_retaining(&bytes, &mut capture).unwrap_err();

        assert_eq!(returned, ordinary);
        assert!(matches!(returned, BrokerSessionDurableError::InvalidClosedValue));
        assert_eq!(capture.retained_request_packet(), Some(original.request_packet()));
        let address = capture.retained_request_packet().unwrap().as_ptr();
        assert!(BrokerSessionDurableRecordV1::decode_retaining(&bytes, &mut capture).is_err());
        assert_eq!(capture.retained_request_packet().unwrap().as_ptr(), address);
    }

    #[test]
    fn actual_second_snapshot_survives_a_failed_unchanged_comparison() {
        let mut fixture = journal::LifecycleTerminalFixture::storage_client();
        let protocol = fixture.currentness.as_ref().unwrap().transcript.protocol();
        let mut before = fixture.journal.read_current(protocol).unwrap();
        before.current_head[0] ^= 1;
        let mut originals = UnchangedOriginalsV1::default();

        assert!(require_unchanged_engine(
            &mut fixture.journal, protocol, &before, Some(&mut originals),
            RetainedCurrentPurposeV1::Storage,
        ).is_err());

        let actual = originals.after.snapshot().unwrap();
        assert_ne!(actual.current_head, before.current_head);
        assert!(!actual.history.as_ref().unwrap().is_empty());
        let cause = originals.failure().unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap();
        assert!(matches!(cause, BrokerSessionSecurityError::Currentness));
    }

    #[test]
    fn actual_replay_stays_parked_when_the_later_endpoint_post_fails() {
        let mut fixture = journal::LifecycleTerminalFixture::storage_client();
        let current = fixture.currentness.as_ref().unwrap();
        let transcript = current.transcript.clone();
        let context = current.context.clone();
        let peer = ObservedBrokerPeerExecutionV1::from_connection(
            fixture.socket.peer(), transcript.broker_process(),
        ).unwrap();
        let mut originals = ReopenCurrentOriginalsV1::default();
        originals.observe_once(&mut fixture.journal, &transcript, &context, &peer).unwrap();
        let history = originals.values().unwrap().0 as *const BrokerSessionDurableHistoryV1;
        let first = originals.before.snapshot().unwrap()
            as *const ProtectedBrokerSessionJournalSnapshotV1;
        let second = originals.unchanged.after.snapshot().unwrap()
            as *const ProtectedBrokerSessionJournalSnapshotV1;
        assert_ne!(first, second);

        journal::LifecycleTerminalFixture::replace_client_key(&fixture.client_path);
        let post = fixture.journal.revalidate_broker_outcome(
            fixture.currentness.take().unwrap(), fixture.socket.peer(),
        );

        assert!(post.is_err());
        assert_eq!(originals.values().unwrap().0 as *const _, history);
        assert_eq!(originals.before.snapshot().unwrap() as *const _, first);
        assert_eq!(originals.unchanged.after.snapshot().unwrap() as *const _, second);
        assert!(originals.traffic.traffic().is_some());
        assert!(originals.failure().is_none());
    }
}
