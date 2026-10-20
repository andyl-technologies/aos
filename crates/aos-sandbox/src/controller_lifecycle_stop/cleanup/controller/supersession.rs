//! Retains exact older kind2 admissions under one genuine Source22 completion.
//!
//! These models cannot append or dispose anything. The parent holds the actual
//! Root48/A8/Source/native C originals and commits these metadata successors in
//! its existing atomic Stop completion transaction. Historical admission rows
//! and financial liabilities remain unchanged.

use super::*;
use crate::cli_model::{OperatorRecoveryRequestV1, PublicMutationRequestV1};
use aos_sandbox_protocol::{
    domain_ledger::provisioning_root::finality_recover::{
        OBSERVATION_ADMISSION_KEY_BYTES_V1,
        public_operation::{
            metadata_complete_admission_receiving_bytes_v1, stop_cleanup_admission_transaction_v1,
            stop_cleanup_superseded_operation_data_v1,
        },
    },
    public_api::request::DormantSandboxRequestKindV1,
};
use std::mem::size_of;

type Cause = Box<dyn Error + Send + Sync>;
type Rows<'a> = aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerRowsDataV2<'a>;

struct Candidate {
    raw: Vec<u8>,
    envelope: Option<PublicMutationRequestV1>,
    request: Option<OperatorRecoveryRequestV1>,
    admission: Option<JournalTransaction>,
    successor: Option<crate::JournalRecord>,
}

impl Candidate {
    fn new(raw: &[u8]) -> Self {
        Self {
            raw: raw.to_vec(),
            envelope: None,
            request: None,
            admission: None,
            successor: None,
        }
    }

    fn observe(&mut self, rows: Rows<'_>, key: &[u8]) -> std::result::Result<(), Cause> {
        let data = Admission::decode_v1(&self.raw)?;
        if data.key_v1().as_slice() != key {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.envelope = Some(PublicMutationRequestV1::decode(data.canonical_request)?);
        let envelope = self
            .envelope
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        let DormantSandboxRequestKindV1::OperatorRecover(request) =
            envelope.decode_validated_kind()?
        else {
            return Err(JournalError::ProtectedBoundary.into());
        };
        self.request = Some(OperatorRecoveryRequestV1::try_from(request)?);
        let request = self
            .request
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if request.resource_id() != data.target
            || request.action() != aos_proto::aos::sandbox::v1::OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY as i32
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.admission = Some(stop_cleanup_admission_transaction_v1(
            data,
            request.idempotency_key(),
        )?);
        self.require_before(rows)?;
        Ok(())
    }

    fn require_before(&self, rows: Rows<'_>) -> std::result::Result<(), JournalError> {
        self.require_members(rows, None)
    }

    fn require_members(
        &self,
        rows: Rows<'_>,
        operation_successor: Option<&crate::JournalRecord>,
    ) -> std::result::Result<(), JournalError> {
        let admission = self
            .admission
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;
        for member in admission.records() {
            let expected = if member.namespace() == RecordNamespace::Operation {
                operation_successor.unwrap_or(member)
            } else {
                member
            };
            if expected.namespace() != member.namespace() || expected.key() != member.key()
                || row(rows, member.namespace(), member.key()) != expected.value()
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        let data = Admission::decode_v1(&self.raw).map_err(|_| JournalError::ProtectedBoundary)?;
        if rows
            .all_records()
            .any(|(ns, key, _)| ns == RecordNamespace::Effect && key.starts_with(&data.operation))
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

pub(super) struct StopRecoverSupersessionOriginalV1 {
    current: Option<Candidate>,
    older: Vec<Candidate>,
    returned: Option<std::result::Result<(), Cause>>,
}

impl StopRecoverSupersessionOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            current: None,
            older: Vec::new(),
            returned: None,
        }
    }

    /// Uses the actual protected prefix to quote all reached models and copies.
    pub(super) fn receiving_demand(controller: &Journal) -> Option<ResourceVector> {
        let mut bytes = size_of::<Self>().checked_mul(3)?;
        let mut count = 0_usize;
        for (key, raw) in controller.records(RecordNamespace::OperatorRecovery) {
            if !is_admission_key(key) {
                continue;
            }
            count = count.checked_add(1)?;
            let protobuf =
                aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1(
                    u64::try_from(raw.len()).ok()?,
                    u64::try_from(
                        size_of::<aos_proto::aos::sandbox::v1::OperatorRecoveryRequest>()
                            .max(size_of::<aos_proto::aos::sandbox::v1::ObjectDescriptor>()),
                    )
                    .ok()?,
                )
                .ok()?;
            bytes = bytes
                .checked_add(metadata_complete_admission_receiving_bytes_v1(
                    raw.len(),
                    raw.len(),
                )?)?
                .checked_add(usize::try_from(protobuf.checked_mul(2)?).ok()?)?
                .checked_add(size_of::<Candidate>().checked_mul(3)?)?
                .checked_add(size_of::<crate::JournalRecord>().checked_mul(4)?)?;
        }
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(
                    D::MetadataEntries,
                    u64::try_from(count.checked_mul(4)?).ok()?,
                ),
        )
    }

    pub(super) fn observe_once(
        &mut self,
        controller: &Journal,
        current_raw: &[u8],
        sample: RawPairedClockSample,
    ) -> std::result::Result<(), JournalError> {
        if self.returned.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.returned = Some(self.observe_body(
            controller.historical_read_view_v1().rows_data_v2(),
            current_raw,
            sample,
        ));
        self.require_before(controller)
    }

    fn observe_body(
        &mut self,
        rows: Rows<'_>,
        current_raw: &[u8],
        sample: RawPairedClockSample,
    ) -> std::result::Result<(), Cause> {
        let current = Admission::decode_v1(current_raw)?;
        self.current = Some(Candidate::new(current_raw));
        let actual_current = self
            .current
            .as_mut()
            .ok_or(JournalError::ProtectedBoundary)?;
        actual_current.observe(rows, &current.key_v1())?;
        let current_request = actual_current
            .request
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?;

        for (namespace, key, raw) in rows.all_records() {
            if namespace != RecordNamespace::OperatorRecovery || !is_admission_key(key) {
                continue;
            }
            let older = Admission::decode_v1(raw)?;
            if older.target != current.target || older.operation == current.operation {
                continue;
            }
            let operation = decode_operation(
                row(rows, RecordNamespace::Operation, &older.operation)
                    .ok_or(JournalError::ProtectedBoundary)?,
            )?;
            if operation
                .public_operation()
                .is_none_or(|public| public.recovery_kind_v1() != PublicRecoveryKindV1::StopCleanup)
                || operation.state() != OperationState::Accepted
            {
                continue;
            }

            // Existing protected admissions precede this held native append.
            // They may have other holders, boots or expired authorization; those
            // historical fields never become current authority for this writer.
            self.older.push(Candidate::new(raw));
            let candidate = self
                .older
                .last_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            candidate.observe(rows, key)?;
            let request = candidate
                .request
                .as_ref()
                .ok_or(JournalError::ProtectedBoundary)?;
            require_same_target(current, current_request, older, request)?;
            let terminal = stop_cleanup_superseded_operation_data_v1(older, operation, sample)?;
            candidate.successor = Some(crate::JournalRecord::put(
                RecordNamespace::Operation,
                older.operation.to_vec(),
                aos_sandbox_protocol::domain_ledger::operation::encode_operation_record(terminal),
            ));
        }
        Ok(())
    }

    pub(super) fn require_before(
        &self,
        controller: &Journal,
    ) -> std::result::Result<(), JournalError> {
        if !matches!(self.returned, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        let rows = controller.historical_read_view_v1().rows_data_v2();
        self.current
            .as_ref()
            .ok_or(JournalError::ProtectedBoundary)?
            .require_before(rows)?;
        for candidate in &self.older {
            candidate.require_before(rows)?;
            if candidate.successor.is_none() {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        Ok(())
    }

    pub(super) fn records(&self) -> impl Iterator<Item = &crate::JournalRecord> {
        self.older
            .iter()
            .filter_map(|candidate| candidate.successor.as_ref())
    }

    /// Rejoins every retained historical member and actual superseded successor.
    ///
    /// The caller separately holds the complete native after-cut. No dynamic
    /// prefix is discarded merely because the final token has four core hashes.
    pub(super) fn require_after(&self, controller: &Journal) -> std::result::Result<(), JournalError> {
        self.require_after_rows(controller.historical_read_view_v1().rows_data_v2())
    }

    fn require_after_rows(&self, rows: Rows<'_>) -> std::result::Result<(), JournalError> {
        if !matches!(self.returned, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        for candidate in &self.older {
            let successor = candidate.successor.as_ref().ok_or(JournalError::ProtectedBoundary)?;
            candidate.require_members(rows, Some(successor))?;
            let admission = Admission::decode_v1(&candidate.raw)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::
                require_stop_cleanup_superseded_operation_data_v1(admission,
                    successor.value().ok_or(JournalError::ProtectedBoundary)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
        }
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.returned
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause.as_ref() as _)
    }
}

fn is_admission_key(key: &[u8]) -> bool {
    let canonical = Admission::key_from_original_v1([0; 16], [0; 32]);
    key.starts_with(&canonical[..OBSERVATION_ADMISSION_KEY_BYTES_V1 - 16 - 32])
}

fn require_same_target(
    current: Admission<'_>,
    current_request: &OperatorRecoveryRequestV1,
    older: Admission<'_>,
    older_request: &OperatorRecoveryRequestV1,
) -> std::result::Result<(), JournalError> {
    let a = current_request.evidence();
    let b = older_request.evidence();
    if older.target != current.target
        || older.project != current.project
        || older.node != current.node
        || older_request.resource_id() != current_request.resource_id()
        || older_request.expected_resource_version() != current_request.expected_resource_version()
        || a.media_type != b.media_type
        || a.sha256 != b.sha256
        || a.encoded_size != b.encoded_size
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn row<'a>(rows: Rows<'a>, namespace: RecordNamespace, key: &[u8]) -> Option<&'a [u8]> {
    rows.all_records()
        .find(|(ns, name, _)| *ns == namespace && *name == key)
        .map(|(_, _, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;
    use buffa::Message as _;
    use std::collections::BTreeMap;

    type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

    // Only canonical DATA recipes are exercised here. No native Source22,
    // Root48, append lender or financial completion is constructed by a test.
    fn fixture(idempotency: &[u8], version: u8) -> (State, Vec<u8>) {
        let request = aos_proto::aos::sandbox::v1::OperatorRecoveryRequest {
            resource_id: vec![1; 16],
            expected_resource_version: vec![version; 32],
            action:
                aos_proto::aos::sandbox::v1::OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY
                    .into(),
            idempotency_key: idempotency.to_vec(),
            evidence: aos_proto::aos::sandbox::v1::ObjectDescriptor {
                media_type: "application/vnd.aos.sandbox.operator-recovery-evidence.v1".to_owned(),
                sha256: vec![6; 32],
                encoded_size: 1,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let canonical = PublicMutationRequestV1::new(
            crate::cli_model::PublicApiAuditMethodV1::OperatorRecover,
            &request.encode_to_vec(),
        )
        .unwrap()
        .encode();
        PublicMutationRequestV1::decode(&canonical)
            .unwrap()
            .decode_validated_kind()
            .unwrap();
        let idempotency_digest = Admission::idempotency_digest_v1([3; 16], idempotency);
        let key = Admission::key_from_original_v1([3; 16], idempotency_digest);
        let admission = Admission {
            operation: Admission::operation_id_v1(&key),
            request_scope: [10; 32],
            target: [1; 16],
            node: [2; 16],
            holder: [3; 16],
            project: [4; 16],
            capability: [5; 16],
            channel: [6; 32],
            authorization_revision: [7; 32],
            idempotency_digest,
            original: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
                [9; 16],
                100,
                10_000_000_000,
            )
            .unwrap(),
            cutoff: 40_000_000_000,
            wall_expiry: 140,
            canonical_request: &canonical,
        };
        let transaction = stop_cleanup_admission_transaction_v1(admission, idempotency).unwrap();
        let state = transaction
            .records()
            .iter()
            .map(|member| {
                (
                    (member.namespace(), member.key().to_vec()),
                    member.value().unwrap().to_vec(),
                )
            })
            .collect();
        let mut raw = vec![0; admission.encoded_bytes_v1().unwrap()];
        admission.encode_into_v1(&mut raw).unwrap();
        (state, raw)
    }

    fn observe(state: &State, current: &[u8]) -> StopRecoverSupersessionOriginalV1 {
        let index = BTreeMap::new();
        let rows = Rows::new(state, &index);
        let now = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [9; 16],
            110,
            20_000_000_000,
        )
        .unwrap();
        let mut original = StopRecoverSupersessionOriginalV1::new();
        original.returned = Some(original.observe_body(rows, current, now));
        original
    }

    #[test]
    fn exact_pending_admissions_become_n_plus_four_without_changing_history() {
        let (mut state, current) = fixture(b"current", 8);
        let (old_state, old) = fixture(b"older", 8);
        state.extend(old_state.clone());
        let original = observe(&state, &current);
        assert!(matches!(original.returned, Some(Ok(()))), "{:?}", original.failure());
        assert_eq!(original.records().count(), 1);
        let old_data = Admission::decode_v1(&old).unwrap();
        let superseded = original.records().next().unwrap();
        assert_eq!(superseded.key(), old_data.operation);
        aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::
            require_stop_cleanup_superseded_operation_data_v1(old_data, superseded.value().unwrap()).unwrap();

        let stop = JournalTransaction::new(
            [11; 16],
            vec![
                crate::JournalRecord::put(
                    RecordNamespace::Effect,
                    effect_key(OperationId::from_bytes([1; 16]), 0).to_vec(),
                    vec![12],
                ),
                crate::JournalRecord::put(RecordNamespace::Operation, vec![1; 16], vec![13]),
                crate::JournalRecord::put(RecordNamespace::DesiredState, vec![14], vec![15]),
            ],
        )
        .unwrap();
        let current_data = Admission::decode_v1(&current).unwrap();
        let now = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [9; 16],
            110,
            20_000_000_000,
        )
        .unwrap();
        let metadata = closed_cleanup_terminal_transaction_data_v2(
            PublicRecoveryKindV1::StopCleanup,
            current_data,
            stop_cleanup_operation_v1(current_data).unwrap(),
            now,
        )
        .unwrap();
        let transaction = atomic_cleanup_transaction(&stop, &metadata, &original).unwrap();
        assert_eq!(transaction.records().len(), 5);
        assert_eq!(&transaction.records()[..3], stop.records());
        assert_eq!(transaction.records()[3], metadata.records()[0]);
        assert_eq!(&transaction.records()[4], superseded);
        for ((namespace, key), value) in &old_state {
            assert_eq!(state.get(&(*namespace, key.clone())), Some(value));
            if *namespace != RecordNamespace::Operation {
                assert!(
                    !transaction
                        .records()
                        .iter()
                        .any(|member| member.namespace() == *namespace
                            && member.key() == key.as_slice())
                );
            }
        }
    }

    #[test]
    fn changed_target_evidence_or_immutable_admission_never_supersedes() {
        let (current_state, current) = fixture(b"current", 8);
        let (older_state, older) = fixture(b"older", 9);
        let mut state = current_state.clone();
        state.extend(older_state);
        assert!(observe(&state, &current).failure().is_some());

        let (older_state, older_same) = fixture(b"older-same", 8);
        let old_data = Admission::decode_v1(&older_same).unwrap();
        let transaction = stop_cleanup_admission_transaction_v1(old_data, b"older-same").unwrap();
        for member in transaction.records() {
            let mut state = current_state.clone();
            state.extend(older_state.clone());
            state
                .get_mut(&(member.namespace(), member.key().to_vec()))
                .unwrap()
                .push(0);
            assert!(observe(&state, &current).failure().is_some());
        }
        let mut state = current_state;
        state.extend(older_state);
        state.insert(
            (
                RecordNamespace::Effect,
                effect_key(OperationId::from_bytes(old_data.operation), 0).to_vec(),
            ),
            vec![0],
        );
        assert!(observe(&state, &current).failure().is_some());
        // Keep an unrelated old fixture live to prove no virtual old writer is
        // being materialized by any of these comparison refusals.
        assert_ne!(older, current);
    }

    #[test]
    fn retained_admission_cause_precedes_later_independent_native_posts() {
        let mut terminal = StopCleanupControllerOriginalV1::new(200);
        terminal.supersession.returned = Some(Err(std::io::Error::other("old admission mismatch").into()));
        terminal.body = Some(Err(JournalError::ProtectedBoundary));
        terminal.select_failure_once();

        terminal.stage.first = Some(First::Funding);
        terminal.stage.funding = Some(Err(ResourceReservationErrorV1::EnrollmentUnavailable));
        terminal.select_failure_once();

        assert!(matches!(terminal.selected, Some(TerminalFailureV1::Supersession)));
        assert!(terminal.failure().unwrap().downcast_ref::<std::io::Error>().is_some());
        assert!(terminal.stage.failure().is_some());
    }

    #[test]
    fn exact_canonical_supersession_is_rejoined_after_append_before_disposal() {
        let (mut state, current) = fixture(b"current", 8);
        let (old_state, _) = fixture(b"older", 8);
        state.extend(old_state.clone());
        let original = observe(&state, &current);
        assert!(matches!(original.returned, Some(Ok(()))), "{:?}", original.failure());
        let index = BTreeMap::new();
        assert!(original.require_after_rows(Rows::new(&state, &index)).is_err());
        for member in original.records() {
            state.insert((member.namespace(), member.key().to_vec()), member.value().unwrap().to_vec());
        }
        original.require_after_rows(Rows::new(&state, &index)).unwrap();
        for ((namespace, key), _) in old_state {
            let mut changed = state.clone();
            changed.get_mut(&(namespace, key)).unwrap().push(0);
            assert!(original.require_after_rows(Rows::new(&changed, &index)).is_err());
        }
    }

    #[test]
    fn canonical_candidate_errors_preserve_service_send_and_sync() {
        fn require_send_sync<T: Send + Sync>() {}
        require_send_sync::<StopRecoverSupersessionOriginalV1>();
    }
}
