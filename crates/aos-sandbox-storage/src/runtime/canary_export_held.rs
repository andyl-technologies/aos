//! Resident, nonadmitting canary-prefix custody under the actual Storage runtime.
//!
//! The installed Host-only receiver donates its original socket and packet
//! before selected parsing. Complete primary/native loans use the sole Core
//! parser and lending cursor. A marker is same-history debt, never a floor:
//! neither its absence nor complete local history permits fresh creation,
//! dispatch, sidecar writes, generation0, positive ACK or Launch.
//!
//! The existing-only sidecar uses the proposed private DATA format:
//!
//! ```text
//! AOSRCH01 | version1 | phase1..4 | length1040 |
//! request402 | response240 | ACK192 | confirmation184 | zero6
//! ```
//!
//! Completed fields never change; unobserved suffixes are zero padding, not
//! zero resources. Four exact rows still do not reconstruct an old worker or
//! prove quiescence, bootstrap currentness, parent funding or rollback absence.

use aos_sandbox::{Journal, JournalLimits, StorageNativeIssuanceEdgeDataV1};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_protocol::storage_root_export::{
    StorageCanaryExportAcknowledgmentV1, StorageCanaryExportConfirmationV1,
    StorageCanaryExportRequestV1, StorageCanaryExportResponseV1,
};
use sha2::{Digest as _, Sha256};

use super::repair_worker_drain::RepairWorkerDispatchGate;
use crate::native_issuance::{StorageNativeIssuanceErrorV1, StorageNativeIssuanceLedgerV1};
use crate::peer::HostRootExportPeerVerifier;
use crate::pin_worker::boottime_now_nanoseconds;
use crate::{StorageAdmissionCoordinator, StorageBrokerError, ZfsWorkerError};

const MAXIMUM_ORIGINAL_NANOSECONDS: u64 = 300_000_000_000;
const PRIMARY_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-primary-history.v1\0";
const NATIVE_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-native-history.v1\0";
const HOLD_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-prefix-negative-hold.v1\0";
const SIDECAR_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.storage.canary-export-held-transaction.v1\0";
const SIDECAR_HISTORY_DOMAIN: &[u8] = b"aos.sandbox.storage.canary-sidecar-history.v1\0";
const SIDECAR_LIMITS: JournalLimits = JournalLimits {
    maximum_journal_bytes: 16_384,
    maximum_record_bytes: 2048,
    maximum_key_bytes: 32,
    maximum_records_per_transaction: 1,
    maximum_transaction_bytes: 4096,
    maximum_transactions: 4,
    maximum_materialized_bytes: 2048,
    maximum_materialized_records: 1,
};

#[derive(Debug, thiserror::Error)]
pub(super) enum CanaryPrefixCause {
    #[error("canary prefix instance is already closed")]
    Closed,
    #[error("canary prefix observation was interrupted")]
    Interrupted,
    #[error("canary prefix original binding was rejected")]
    Binding,
    #[error("independent attempt-bound floor and complete components are missing")]
    MissingProducer,
    #[error(transparent)]
    Request(aos_sandbox_protocol::storage_root_export::StorageRootExportProtocolErrorV1),
    #[error(transparent)]
    Socket(aos_sandbox_linux::seqpacket::RecordBindingError),
    #[error(transparent)]
    Kernel(aos_sandbox_linux::Error),
    #[error(transparent)]
    Clock(ZfsWorkerError),
    #[error(transparent)]
    Primary(StorageBrokerError),
    #[error(transparent)]
    Native(StorageNativeIssuanceErrorV1),
    #[error(transparent)]
    History(aos_sandbox::StorageNativeIssuanceHistoryErrorV1),
    #[error(transparent)]
    PrimaryHistory(aos_sandbox::journal::StorageCanaryExportHistoryErrorV1),
    #[error(transparent)]
    Sidecar(aos_sandbox::JournalError),
}

/// Owns completed historical observations, not self-borrowed Journal loans.
struct OriginalHistoryCut {
    digest: [u8; 32],
    limits: JournalLimits,
    physical_bytes: u64,
    next_sequence: u64,
    transactions: usize,
    records: usize,
}

pub(super) struct CanaryExportHeldV1 {
    attempted: bool,
    socket: Option<DescriptorSubjectSocket>,
    record: Option<ReceivedDescriptorRecord>,
    request: Option<StorageCanaryExportRequestV1>,
    hold_identity: Option<[u8; 32]>,
    primary: Option<OriginalHistoryCut>,
    native: Option<OriginalHistoryCut>,
    sidecar: Option<Journal>,
    sidecar_recovery: Option<aos_sandbox::journal::RecoveryReport>,
    sidecar_rows: [Option<[u8; 1040]>; 4],
    sidecar_cut: Option<OriginalHistoryCut>,
    marker: Option<[u8; 208]>,
    first_failure: Option<CanaryPrefixCause>,
}

impl CanaryExportHeldV1 {
    pub(super) const fn new() -> Self {
        Self {
            attempted: false,
            socket: None,
            record: None,
            request: None,
            hold_identity: None,
            primary: None,
            native: None,
            sidecar: None,
            sidecar_recovery: None,
            sidecar_rows: [None; 4],
            sidecar_cut: None,
            marker: None,
            first_failure: None,
        }
    }

    // The caller checks vacancy before these infallible owner moves. No second
    // packet can recover a failed/interrupted instance or renew its deadline.
    pub(super) fn is_unused(&self) -> bool {
        !self.attempted && self.socket.is_none() && self.record.is_none()
    }

    pub(super) fn park_original(
        &mut self,
        mut socket: DescriptorSubjectSocket,
        record: ReceivedDescriptorRecord,
    ) {
        self.attempted = true;
        socket.begin_original_retention_v1();
        self.socket = Some(socket);
        self.record = Some(record);
    }

    pub(super) fn observe_original(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        gate: &RepairWorkerDispatchGate,
        broker_instance_id: &[u8; 16],
        verifier: &HostRootExportPeerVerifier,
    ) {
        // This instance is never reopened, including after a caught unwind.
        let observation = CanaryObservation { owner: self };
        let result = observation.owner.observe_inner(
            coordinator, native, gate, broker_instance_id, verifier,
        );
        observation.owner.first_failure = Some(match result {
            Ok(()) => CanaryPrefixCause::MissingProducer,
            Err(cause) => cause,
        });
    }

    fn observe_inner(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
        native: Option<&mut StorageNativeIssuanceLedgerV1>,
        gate: &RepairWorkerDispatchGate,
        broker_instance_id: &[u8; 16],
        verifier: &HostRootExportPeerVerifier,
    ) -> Result<(), CanaryPrefixCause> {
        let socket = self.socket.as_mut().ok_or(CanaryPrefixCause::Closed)?;
        let record = self.record.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        socket.validate_received_origin(record).map_err(CanaryPrefixCause::Socket)?;
        let execution = verifier.verify_connection(socket.peer())
            .map_err(|()| CanaryPrefixCause::Binding)?;
        verifier.verify_record(execution, socket.peer(), record.subject())
            .map_err(|()| CanaryPrefixCause::Binding)?;
        if !record.descriptors().is_empty() {
            return Err(CanaryPrefixCause::Binding);
        }
        self.request = Some(StorageCanaryExportRequestV1::decode(record.payload())
            .map_err(CanaryPrefixCause::Request)?);
        self.require_original_clock()?;

        let request = self.request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let request_digest = request.digest().map_err(CanaryPrefixCause::Request)?;
        let mut identity = Sha256::new();
        identity.update(HOLD_DOMAIN);
        identity.update(broker_instance_id);
        identity.update(request_digest);
        let identity = identity.finalize().into();
        self.hold_identity = Some(identity);
        gate.begin_canary_hold(identity).map_err(|()| CanaryPrefixCause::Binding)?;

        self.capture_primary(coordinator)?;
        self.require_original_clock()?;
        let native = native.ok_or(CanaryPrefixCause::MissingProducer)?;
        self.capture_native(native, coordinator)?;
        self.require_original_clock()?;
        self.capture_sidecar()?;
        self.require_original_clock()?;
        gate.require_canary_hold(&identity).map_err(|()| CanaryPrefixCause::Binding)?;
        let socket = self.socket.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let record = self.record.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        verifier.verify_record(execution, socket.peer(), record.subject())
            .map_err(|()| CanaryPrefixCause::Binding)?;

        // All observations are DATA. In particular, marker absence does not
        // authenticate an unused cut after whole-primary rollback. No effect,
        // marker write, positive reply or ACK continuation exists in this cut.
        Ok(())
    }

    fn require_original_clock(&self) -> Result<(), CanaryPrefixCause> {
        let request = self.request.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let boot = KernelBootId::current().map_err(CanaryPrefixCause::Kernel)?;
        let now = boottime_now_nanoseconds().map_err(CanaryPrefixCause::Clock)?;
        request.deadline_boottime_nanoseconds.checked_sub(now)
            .filter(|remaining| *remaining != 0 && *remaining <= MAXIMUM_ORIGINAL_NANOSECONDS)
            .ok_or(CanaryPrefixCause::Binding)?;
        if boot.into_bytes() != request.boot_id {
            return Err(CanaryPrefixCause::Binding);
        }
        Ok(())
    }

    fn capture_primary(
        &mut self,
        coordinator: &StorageAdmissionCoordinator,
    ) -> Result<(), CanaryPrefixCause> {
        let mut history = coordinator.borrow_canary_bootstrap_primary_original()
            .map_err(CanaryPrefixCause::Primary)?;
        self.require_original_clock()?;
        let limits = history.opened_limits();
        let physical_bytes = history.physical_bytes();
        let next_sequence = history.next_sequence();
        let mut hash = Sha256::new();
        hash.update(PRIMARY_HISTORY_DOMAIN);
        let mut transactions = 0usize;
        let mut records = 0usize;
        let mut cursor = history.replay().map_err(CanaryPrefixCause::PrimaryHistory)?;
        while let Some(edge) = cursor.next_edge().map_err(CanaryPrefixCause::History)? {
            self.require_original_clock()?;
            hash_edge(&mut hash, &edge);
            transactions = transactions.checked_add(1).ok_or(CanaryPrefixCause::Binding)?;
            records = records.checked_add(edge.transaction().records().len())
                .ok_or(CanaryPrefixCause::Binding)?;
            for record in edge.transaction().records() {
                if let Some(marker) = coordinator.observe_canary_bootstrap_marker_original(
                    edge.transaction(), record,
                ).map_err(CanaryPrefixCause::Primary)? {
                    if self.marker.is_some() {
                        return Err(CanaryPrefixCause::Binding);
                    }
                    self.marker = Some(marker);
                }
            }
        }
        cursor.finish().map_err(CanaryPrefixCause::History)?;
        self.primary = Some(OriginalHistoryCut {
            digest: hash.finalize().into(),
            limits,
            physical_bytes,
            next_sequence,
            transactions,
            records,
        });
        Ok(())
    }

    fn capture_native(
        &mut self,
        native: &mut StorageNativeIssuanceLedgerV1,
        coordinator: &StorageAdmissionCoordinator,
    ) -> Result<(), CanaryPrefixCause> {
        let mut history = native.borrow_canary_bootstrap_native_original(coordinator)
            .map_err(CanaryPrefixCause::Native)?;
        self.require_original_clock()?;
        let limits = history.opened_limits();
        let physical_bytes = history.physical_bytes();
        let next_sequence = history.next_sequence();
        let mut hash = Sha256::new();
        hash.update(NATIVE_HISTORY_DOMAIN);
        let mut transactions = 0usize;
        let mut records = 0usize;
        let mut cursor = history.replay().map_err(CanaryPrefixCause::History)?;
        while let Some(edge) = cursor.next_edge().map_err(CanaryPrefixCause::History)? {
            self.require_original_clock()?;
            hash_edge(&mut hash, &edge);
            transactions = transactions.checked_add(1).ok_or(CanaryPrefixCause::Binding)?;
            records = records.checked_add(edge.transaction().records().len())
                .ok_or(CanaryPrefixCause::Binding)?;
        }
        cursor.finish().map_err(CanaryPrefixCause::History)?;
        self.native = Some(OriginalHistoryCut {
            digest: hash.finalize().into(),
            limits,
            physical_bytes,
            next_sequence,
            transactions,
            records,
        });
        Ok(())
    }

    fn capture_sidecar(&mut self) -> Result<(), CanaryPrefixCause> {
        // Existing-only is essential. Missing/torn/ambiguous names retain the
        // actual refusal; this method cannot create, repair or settle a pair.
        self.require_original_clock()?;
        let (journal, recovery) = Journal::open_existing_protected_at(
            std::path::Path::new("/var/lib/aos/sandbox-storage"),
            "storage-canary-export.journal",
            SIDECAR_LIMITS,
        ).map_err(CanaryPrefixCause::Sidecar)?;
        self.sidecar = Some(journal);
        self.sidecar_recovery = Some(recovery);
        self.require_original_clock()?;
        let journal = self.sidecar.as_ref().ok_or(CanaryPrefixCause::Closed)?;
        let mut history = journal.capture_storage_canary_export_history_v1()
            .map_err(CanaryPrefixCause::PrimaryHistory)?;
        self.require_original_clock()?;
        let limits = history.opened_limits();
        let physical_bytes = history.physical_bytes();
        let next_sequence = history.next_sequence();
        let mut hash = Sha256::new();
        hash.update(SIDECAR_HISTORY_DOMAIN);
        let mut count = 0usize;
        let mut previous = [0u8; 1040];
        let mut original_key = None;
        let mut phase_three_cut = None;
        let mut cursor = history.replay().map_err(CanaryPrefixCause::PrimaryHistory)?;
        while let Some(edge) = cursor.next_edge().map_err(CanaryPrefixCause::PrimaryHistory)? {
            self.require_original_clock()?;
            if count >= self.sidecar_rows.len() {
                return Err(CanaryPrefixCause::Binding);
            }
            let [record] = edge.transaction().records() else {
                return Err(CanaryPrefixCause::Binding);
            };
            let value: [u8; 1040] = record.value()
                .and_then(|value| value.try_into().ok())
                .ok_or(CanaryPrefixCause::Binding)?;
            // Park each actual row before any private phase/body comparison.
            self.sidecar_rows[count] = Some(value);
            require_sidecar_row(&value, count, &previous, record.key(), phase_three_cut)?;
            let key: [u8; 32] = record.key().try_into()
                .map_err(|_| CanaryPrefixCause::Binding)?;
            if original_key.is_some_and(|original| original != key) {
                return Err(CanaryPrefixCause::Binding);
            }
            original_key = Some(key);
            let mut transaction = Sha256::new();
            transaction.update(SIDECAR_TRANSACTION_DOMAIN);
            transaction.update(Sha256::digest(previous));
            transaction.update(value);
            let transaction = transaction.finalize();
            if edge.transaction().id().as_slice() != &transaction[..16] {
                return Err(CanaryPrefixCause::Binding);
            }
            hash_canary_edge(&mut hash, &edge);
            if count == 2 {
                // The digest excludes phase4, so its stored confirmation does
                // not require a self-digest fixpoint. Only hash state is copied.
                phase_three_cut = Some(hash.clone().finalize().into());
            }
            previous = value;
            count += 1;
        }
        cursor.finish().map_err(CanaryPrefixCause::PrimaryHistory)?;
        self.sidecar_cut = Some(OriginalHistoryCut {
            digest: hash.finalize().into(),
            limits,
            physical_bytes,
            next_sequence,
            transactions: count,
            records: count,
        });
        // Even four exact phases remain historical DATA. No resident worker,
        // independent floor or authenticated bank is synthesized on restart.
        Ok(())
    }
}

// A caught unwind cannot leave the selected socket usable. The real panic
// propagates unchanged; Interrupted is a negative marker, not its cause.
struct CanaryObservation<'owner> {
    owner: &'owner mut CanaryExportHeldV1,
}

impl Drop for CanaryObservation<'_> {
    fn drop(&mut self) {
        if self.owner.first_failure.is_none() {
            self.owner.first_failure = Some(CanaryPrefixCause::Interrupted);
        }
        if let Some(socket) = &mut self.owner.socket {
            socket.close();
        }
    }
}

impl Drop for CanaryExportHeldV1 {
    fn drop(&mut self) {
        if let Some(socket) = &mut self.socket {
            socket.close();
        }
        // This shuts down an original channel, not a worker or durable debt.
        // No drop path settles the held gate, writes state or claims Drain.
    }
}

fn hash_edge(hash: &mut Sha256, edge: &StorageNativeIssuanceEdgeDataV1<'_>) {
    hash.update(edge.begin_sequence().to_be_bytes());
    hash.update(edge.commit_sequence().to_be_bytes());
    hash.update(edge.next_sequence().to_be_bytes());
    hash.update(edge.begin_offset().to_be_bytes());
    hash.update(edge.end_offset().to_be_bytes());
    hash.update(edge.transaction().id());
    hash.update((edge.transaction().records().len() as u64).to_be_bytes());
    for record in edge.transaction().records() {
        hash.update([record.namespace() as u8]);
        hash.update((record.key().len() as u64).to_be_bytes());
        hash.update(record.key());
        match record.value() {
            Some(value) => {
                hash.update([1]);
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value);
            }
            None => hash.update([0]),
        }
    }
}

fn hash_canary_edge(
    hash: &mut Sha256,
    edge: &aos_sandbox::journal::StorageCanaryExportEdgeDataV1<'_>,
) {
    hash.update(edge.begin_sequence().to_be_bytes());
    hash.update(edge.commit_sequence().to_be_bytes());
    hash.update(edge.next_sequence().to_be_bytes());
    hash.update(edge.begin_offset().to_be_bytes());
    hash.update(edge.end_offset().to_be_bytes());
    hash.update(edge.transaction().id());
    for record in edge.transaction().records() {
        hash.update(record.key());
        if let Some(value) = record.value() {
            hash.update(value);
        }
    }
}

fn require_sidecar_row(
    value: &[u8; 1040],
    index: usize,
    previous: &[u8; 1040],
    key: &[u8],
    phase_three_cut: Option<[u8; 32]>,
) -> Result<(), CanaryPrefixCause> {
    let phase = u16::try_from(index + 1).map_err(|_| CanaryPrefixCause::Binding)?;
    if &value[..8] != b"AOSRCH01"
        || value[8..10] != 1u16.to_be_bytes()
        || value[10..12] != phase.to_be_bytes()
        || value[12..16] != 1040u32.to_be_bytes()
        || value[1034..] != [0; 6]
        || index > 3
    {
        return Err(CanaryPrefixCause::Binding);
    }
    let request = StorageCanaryExportRequestV1::decode(&value[16..418])
        .map_err(CanaryPrefixCause::Request)?;
    if index > 0 && value[16..418] != previous[16..418] {
        return Err(CanaryPrefixCause::Binding);
    }
    if index == 0 {
        return if value[418..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err(CanaryPrefixCause::Binding)
        };
    }
    let response = StorageCanaryExportResponseV1::decode(&value[418..658])
        .map_err(CanaryPrefixCause::Request)?;
    if response.nonce != request.nonce
        || response.held_identity.as_slice() != key
        || response.request_digest != request.digest().map_err(CanaryPrefixCause::Request)?
        || (index > 1 && value[418..658] != previous[418..658])
    {
        return Err(CanaryPrefixCause::Binding);
    }
    if index == 1 {
        return if value[658..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err(CanaryPrefixCause::Binding)
        };
    }
    let acknowledgment = StorageCanaryExportAcknowledgmentV1::decode(&value[658..850])
        .map_err(CanaryPrefixCause::Request)?;
    if acknowledgment.nonce != request.nonce
        || acknowledgment.request_digest != response.request_digest
        || acknowledgment.held_identity != response.held_identity
        || acknowledgment.measured_response_digest != response.digest()
            .map_err(CanaryPrefixCause::Request)?
        || acknowledgment.deadline_boottime_nanoseconds != request.deadline_boottime_nanoseconds
        || (index > 2 && value[658..850] != previous[658..850])
    {
        return Err(CanaryPrefixCause::Binding);
    }
    if index == 2 {
        return if value[850..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err(CanaryPrefixCause::Binding)
        };
    }
    let confirmation = StorageCanaryExportConfirmationV1::decode(&value[850..1034])
        .map_err(CanaryPrefixCause::Request)?;
    if confirmation.nonce != request.nonce
        || confirmation.request_digest != response.request_digest
        || confirmation.held_identity != response.held_identity
        || confirmation.generation_zero_digest != acknowledgment.generation_zero_digest
        || Some(confirmation.accepted_native_cut_digest) != phase_three_cut
        || confirmation.deadline_boottime_nanoseconds != request.deadline_boottime_nanoseconds
    {
        return Err(CanaryPrefixCause::Binding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slots_do_not_contain_a_floor_or_completed_observation() {
        let owner = CanaryExportHeldV1::new();

        assert!(owner.is_unused());
        assert!(owner.primary.is_none());
        assert!(owner.native.is_none());
        assert!(owner.marker.is_none());
        assert!(owner.first_failure.is_none());
    }

    #[test]
    fn interrupted_observation_is_permanently_negative_without_an_original_socket() {
        let mut owner = CanaryExportHeldV1::new();
        owner.attempted = true;

        drop(CanaryObservation { owner: &mut owner });

        assert!(!owner.is_unused());
        assert!(matches!(owner.first_failure, Some(CanaryPrefixCause::Interrupted)));
        assert!(owner.record.is_none());
    }

    #[test]
    fn sidecar_recipe_retains_all_eight_fixed_ceilings_as_data() {
        assert_eq!(SIDECAR_LIMITS.maximum_journal_bytes, 16_384);
        assert_eq!(SIDECAR_LIMITS.maximum_record_bytes, 2048);
        assert_eq!(SIDECAR_LIMITS.maximum_key_bytes, 32);
        assert_eq!(SIDECAR_LIMITS.maximum_records_per_transaction, 1);
        assert_eq!(SIDECAR_LIMITS.maximum_transaction_bytes, 4096);
        assert_eq!(SIDECAR_LIMITS.maximum_transactions, 4);
        assert_eq!(SIDECAR_LIMITS.maximum_materialized_bytes, 2048);
        assert_eq!(SIDECAR_LIMITS.maximum_materialized_records, 1);
    }
}
