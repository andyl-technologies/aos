//! Classifies exact historical Stop-cleanup Recover families under maintenance.
//!
//! The caller pays this finite reader before decoding and retains the actual
//! current C/Source/native interval. Canonical four-row admissions authenticate
//! comparison history only. Neither an old Accepted Recover nor these returned
//! operation identities grants effects, finance, a deadline or native custody.

use std::{error::Error, mem::size_of};

use aos_sandbox_model::{OperationId, ProjectId, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::{
    domain_ledger::{
        operation::{OperationRecord, decode_operation},
        provisioning_root::finality_recover::{
            CreateFinalityObservationAdmissionDataV1 as Admission,
            OBSERVATION_ADMISSION_KEY_BYTES_V1,
            public_operation::{
                metadata_complete_admission_receiving_bytes_v1,
                require_closed_cleanup_completed_operation_data_v2,
                require_stop_cleanup_superseded_operation_data_v1,
                stop_cleanup_admission_transaction_v1,
            },
        },
        public_operation::{OperationState, PublicRecoveryKindV1},
        readonly::HistoricalLedgerRowsDataV2,
    },
    public_api::request::DormantSandboxRequestKindV1,
};

use crate::{
    Journal, JournalError, JournalTransaction, RecordNamespace,
    cli_model::{OperatorRecoveryRequestV1, PublicApiAuditMethodV1, PublicMutationRequestV1},
    lifecycle::completed_stop::CompletedStopHistoryOriginalV1,
};

type Cause = Box<dyn Error + Send + Sync>;
const CLOSED: JournalError = JournalError::ProtectedBoundary;

#[derive(Clone, Copy)]
struct AdmissionCoordinates {
    operation: OperationId,
    request: [u8; 32],
    node: [u8; 16],
    state: OperationState,
}

struct AdmissionOriginal {
    key: Vec<u8>,
    raw: Vec<u8>,
    envelope: Option<PublicMutationRequestV1>,
    request: Option<OperatorRecoveryRequestV1>,
    transaction: Option<JournalTransaction>,
    operation: Option<OperationRecord>,
    result: Option<Result<AdmissionCoordinates, Cause>>,
}

impl AdmissionOriginal {
    fn new(key: &[u8], raw: &[u8]) -> Self {
        Self {
            key: key.to_vec(),
            raw: raw.to_vec(),
            envelope: None,
            request: None,
            transaction: None,
            operation: None,
            result: None,
        }
    }

    fn observe(
        &mut self,
        rows: HistoricalLedgerRowsDataV2<'_>,
        target: OperationId,
        project: ProjectId,
    ) -> Result<(), JournalError> {
        self.result = Some(self.observe_body(rows, target, project));
        self.completed().map(|_| ())
    }

    fn observe_body(
        &mut self,
        rows: HistoricalLedgerRowsDataV2<'_>,
        target: OperationId,
        project: ProjectId,
    ) -> Result<AdmissionCoordinates, Cause> {
        let data = Admission::decode_v1(&self.raw)?;
        if data.key_v1().as_slice() != self.key.as_slice()
            || data.target != *target.as_bytes()
            || data.project != *project.as_bytes()
        {
            return Err(CLOSED.into());
        }
        self.envelope = Some(PublicMutationRequestV1::decode(data.canonical_request)?);
        let envelope = self.envelope.as_ref().ok_or(CLOSED)?;
        if envelope.method() != PublicApiAuditMethodV1::OperatorRecover {
            return Err(CLOSED.into());
        }
        let DormantSandboxRequestKindV1::OperatorRecover(request) =
            envelope.decode_validated_kind()?
        else {
            return Err(CLOSED.into());
        };
        self.request = Some(OperatorRecoveryRequestV1::try_from(request)?);
        let request = self.request.as_ref().ok_or(CLOSED)?;
        if request.action()
            != aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY
                as i32
            || request.resource_id() != data.target
        {
            return Err(CLOSED.into());
        }
        self.transaction = Some(stop_cleanup_admission_transaction_v1(
            data,
            request.idempotency_key(),
        )?);
        let transaction = self.transaction.as_ref().ok_or(CLOSED)?;
        let operation = OperationId::from_bytes(data.operation);
        let raw_operation = row(rows, RecordNamespace::Operation, operation.as_bytes())?;
        self.operation = Some(decode_operation(raw_operation)?);
        let actual = self.operation.as_ref().ok_or(CLOSED)?;
        match actual.state() {
            OperationState::Accepted => {
                let admitted = transaction
                    .records()
                    .iter()
                    .find(|member| member.namespace() == RecordNamespace::Operation)
                    .ok_or(CLOSED)?;
                if admitted.key() != operation.as_bytes() || admitted.value() != Some(raw_operation)
                {
                    return Err(CLOSED.into());
                }
            }
            OperationState::Succeeded => {
                require_closed_cleanup_completed_operation_data_v2(
                    PublicRecoveryKindV1::StopCleanup,
                    data,
                    raw_operation,
                )?;
                if actual.public_operation().and_then(|public|
                    public.completed_wall_seconds_v1()).is_none_or(|wall| wall >= data.wall_expiry)
                {
                    return Err(CLOSED.into());
                }
            }
            OperationState::PermanentlyBlocked => {
                // Only the canonical kind2 supersession is historical family
                // DATA. The terminal tag alone cannot admit an old operation.
                require_stop_cleanup_superseded_operation_data_v1(data, raw_operation)?;
            }
            _ => return Err(CLOSED.into()),
        }
        // The Operation alone may advance through the sole terminal recipe.
        // Admission, authorization scope and exact idempotency decision remain
        // byte-literal, including for an older still-Accepted A8 Recover.
        for member in transaction.records() {
            if member.namespace() != RecordNamespace::Operation
                && row(rows, member.namespace(), member.key())? != member.value().ok_or(CLOSED)?
            {
                return Err(CLOSED.into());
            }
        }
        if rows.all_records().any(|(namespace, key, _)| {
            namespace == RecordNamespace::Effect && key.starts_with(operation.as_bytes())
        }) {
            return Err(CLOSED.into());
        }
        Ok(AdmissionCoordinates {
            operation,
            request: data.request_digest_v1(),
            node: data.node,
            state: actual.state(),
        })
    }

    fn completed(&self) -> Result<AdmissionCoordinates, JournalError> {
        self.result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(CLOSED)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.result
            .as_ref()?
            .as_ref()
            .err()
            .map(|cause| cause.as_ref() as _)
    }

    fn shares_target_fence(&self, current: &Self) -> bool {
        let (Some(old), Some(current)) = (self.request.as_ref(), current.request.as_ref()) else {
            return false;
        };
        let old_evidence = old.evidence();
        let current_evidence = current.evidence();
        old.resource_id() == current.resource_id()
            && old.expected_resource_version() == current.expected_resource_version()
            && old_evidence.media_type == current_evidence.media_type
            && old_evidence.sha256 == current_evidence.sha256
            && old_evidence.encoded_size == current_evidence.encoded_size
    }

    fn completed_wall(&self) -> Option<i64> {
        self.operation.as_ref()?.public_operation()?.completed_wall_seconds_v1()
    }
}

#[derive(Clone, Copy)]
struct Family {
    old: OperationId,
    current: OperationId,
}

/// Retains only the exact proved history IDs beside the canonical models.
///
/// The enclosing maintenance loan must rejoin its shared history's exact C
/// and Source cut before consulting these passive family comparisons.
pub(super) struct CatalogMaintenanceRecoverFamilyOriginalV1 {
    admissions: Vec<AdmissionOriginal>,
    families: Vec<Family>,
    returned: Option<Result<(), Cause>>,
    reentered: bool,
}

impl CatalogMaintenanceRecoverFamilyOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            admissions: Vec::new(),
            families: Vec::new(),
            returned: None,
            reentered: false,
        }
    }

    /// Prices every actual admission extent before request/model construction.
    ///
    /// The sole canonical admission supplier bounds all four members and their
    /// candidate copies. The shared protobuf supplier additionally prices the
    /// generated request, its validator clones and the owned checked adapter.
    pub(super) fn receiving_demand_v1(controller: &Journal) -> Option<ResourceVector> {
        let mut bytes = size_of::<Self>().checked_mul(3)?;
        let mut count = 0_usize;
        for (key, raw) in controller.records(RecordNamespace::OperatorRecovery) {
            if !is_admission_key(key) {
                continue;
            }
            count = count.checked_add(1)?;
            let canonical = metadata_complete_admission_receiving_bytes_v1(raw.len(), raw.len())?;
            let width = size_of::<aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryRequest>()
                .max(size_of::<aos_sandbox_api::aos::sandbox::v1::ObjectDescriptor>());
            let protobuf =
                aos_sandbox_broker_session_protocol::receiving_geometry::protobuf_carriers_v1(
                    u64::try_from(raw.len()).ok()?,
                    u64::try_from(width).ok()?,
                )
                .ok()?;
            bytes = bytes
                .checked_add(canonical)?
                .checked_add(usize::try_from(protobuf.checked_mul(2)?).ok()?)?
                .checked_add(size_of::<AdmissionOriginal>().checked_mul(3)?)?;
        }
        // Each proved Stop has a distinct protected Operation row, so the full
        // actual C row count bounds the fixed family/result carriers without
        // decoding either C or Source before this invoice has been paid.
        bytes = bytes.checked_add(
            controller
                .all_records()
                .count()
                .checked_mul(size_of::<Family>())?
                .checked_mul(3)?,
        )?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(
                    D::MetadataEntries,
                    u64::try_from(count.checked_mul(4)?).ok()?,
                ),
        )
    }

    /// Selects strict canonical families from actual held C and A8 history.
    ///
    /// This accepts one unique canonical Succeeded Recover per proved Stop.
    /// Only that Stop's exact A8-named older Recover may remain Accepted.
    /// Other older operations require the sole canonical superseded kind2
    /// successor and the current successful Recover's exact target fence. The
    /// target admission requires Stop Applying; after its atomic C4 success a
    /// new cleanup admission cannot select that Stop. Multiple successes are
    /// consequently ambiguous history and are refused rather than guessed.
    pub(super) fn observe_once_v1(
        &mut self,
        controller: &Journal,
        history: &CompletedStopHistoryOriginalV1,
    ) -> Result<(), JournalError> {
        if self.returned.is_some() {
            self.reentered = true;
            return Err(CLOSED);
        }
        self.returned = Some(self.observe_body(controller, history));
        self.require_completed()
    }

    fn observe_body(
        &mut self,
        controller: &Journal,
        history: &CompletedStopHistoryOriginalV1,
    ) -> Result<(), Cause> {
        controller.ensure_protected_authority()?;
        let rows = controller.historical_read_view_v1().rows_data_v2();
        for stop in history.entries_v1()? {
            let completion = stop.completion_v1().ok_or(CLOSED)?;
            let binding = completion.binding_v1();
            if binding.operation != stop.operation_v1() {
                return Err(CLOSED.into());
            }
            let start = self.admissions.len();
            for (key, raw) in controller.records(RecordNamespace::OperatorRecovery) {
                if !is_admission_key(key) {
                    continue;
                }
                Admission::require_key_v1(key)?;
                let data = Admission::decode_v1(raw)?;
                if data.key_v1().as_slice() != key {
                    return Err(CLOSED.into());
                }
                if data.target != *stop.operation_v1().as_bytes() {
                    continue;
                }
                self.admissions
                    .try_reserve_exact(1)
                    .map_err(|_| JournalError::JournalTooLarge)?;
                self.admissions.push(AdmissionOriginal::new(key, raw));
                self.admissions.last_mut().ok_or(CLOSED)?.observe(
                    rows,
                    stop.operation_v1(),
                    stop.project_v1(),
                )?;
            }
            let family = select_family(
                &self.admissions[start..],
                binding.recovery,
                *binding.recovery_request.as_bytes(),
            )?;
            if self
                .families
                .iter()
                .any(|old| old.old == family.old || old.current == family.current)
            {
                return Err(CLOSED.into());
            }
            self.families
                .try_reserve_exact(1)
                .map_err(|_| JournalError::JournalTooLarge)?;
            self.families.push(family);
        }
        Ok(())
    }

    fn require_completed(&self) -> Result<(), JournalError> {
        if self.reentered || !matches!(self.returned, Some(Ok(()))) || self.failure().is_some() {
            return Err(CLOSED);
        }
        Ok(())
    }

    /// Compares one exact allowed historical ID without issuing a permission.
    pub(super) fn operation_is_proved_v1(&self, operation: OperationId) -> bool {
        self.require_completed().is_ok()
            && self
                .admissions
                .iter()
                .any(|admission| admission.completed().is_ok_and(|data| data.operation == operation))
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.admissions
            .iter()
            .find_map(AdmissionOriginal::failure)
            .or_else(|| {
                self.returned
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref() as _)
            })
            .or_else(|| self.reentered.then_some(&CLOSED as _))
    }
}

fn select_family(
    admissions: &[AdmissionOriginal],
    old: OperationId,
    request: [u8; 32],
) -> Result<Family, JournalError> {
    let mut historical = None;
    let mut current = None;
    for admission in admissions {
        let data = admission.completed()?;
        if data.operation == old {
            if historical.replace(data).is_some() || data.request != request {
                return Err(CLOSED);
            }
        } else if !matches!(data.state, OperationState::Succeeded | OperationState::PermanentlyBlocked) {
            return Err(CLOSED);
        }
        if data.state == OperationState::Succeeded && current.replace(data).is_some() {
            return Err(CLOSED);
        }
    }
    let historical = historical.ok_or(CLOSED)?;
    let current = current.ok_or(CLOSED)?;
    let current_original = admissions.iter()
        .find(|admission| admission.completed().is_ok_and(|data| data.operation == current.operation))
        .ok_or(CLOSED)?;
    if historical.node != current.node {
        return Err(CLOSED);
    }
    for admission in admissions {
        let data = admission.completed()?;
        if data.state == OperationState::PermanentlyBlocked
            && (data.node != current.node
                || !admission.shares_target_fence(current_original)
                || admission.completed_wall() != current_original.completed_wall())
        {
            return Err(CLOSED);
        }
    }
    Ok(Family {
        old,
        current: current.operation,
    })
}

fn is_admission_key(key: &[u8]) -> bool {
    let canonical = Admission::key_from_original_v1([0; 16], [0; 32]);
    key.starts_with(&canonical[..OBSERVATION_ADMISSION_KEY_BYTES_V1 - 16 - 32])
}

fn row<'rows>(
    rows: HistoricalLedgerRowsDataV2<'rows>,
    namespace: RecordNamespace,
    key: &[u8],
) -> Result<&'rows [u8], JournalError> {
    rows.all_records()
        .find(|(actual, name, _)| *actual == namespace && *name == key)
        .map(|(_, _, value)| value)
        .ok_or(CLOSED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
    use aos_sandbox_protocol::domain_ledger::provisioning_root::finality_recover::public_operation::{
        closed_cleanup_terminal_transaction_data_v2, stop_cleanup_operation_v1,
        stop_cleanup_superseded_operation_data_v1,
    };
    use buffa::Message as _;

    type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

    struct Fixture {
        state: State,
        key: Vec<u8>,
        raw: Vec<u8>,
        operation: OperationId,
        request: [u8; 32],
    }

    // These are the actual canonical admission/terminal DATA encoders. They
    // construct no Journal, shared-history proof, native receiver or payer.
    fn fixture(idempotency: &[u8], succeeded: bool) -> Fixture {
        fixture_with_fence(idempotency, succeeded, 9, 6)
    }

    fn fixture_with_fence(idempotency: &[u8], succeeded: bool, version: u8, evidence: u8) -> Fixture {
        fixture_with_clock(idempotency, succeeded, version, evidence, 100, 140)
    }

    fn fixture_with_clock(idempotency: &[u8], succeeded: bool, version: u8, evidence: u8,
        accepted_wall: i64, wall_expiry: i64) -> Fixture {
        let request = aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryRequest {
            resource_id: vec![1; 16],
            expected_resource_version: vec![version; 32],
            action:
                aos_sandbox_api::aos::sandbox::v1::OperatorRecoveryAction::OPERATOR_RECOVERY_ACTION_RETRY
                    .into(),
            idempotency_key: idempotency.to_vec(),
            evidence: aos_sandbox_api::aos::sandbox::v1::ObjectDescriptor {
                media_type: "application/vnd.aos.sandbox.operator-recovery-evidence.v1".to_owned(),
                sha256: vec![evidence; 32],
                encoded_size: 1,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        };
        let envelope = PublicMutationRequestV1::new(
            PublicApiAuditMethodV1::OperatorRecover,
            &request.encode_to_vec(),
        )
        .unwrap();
        // Framing alone does not validate the closed public descriptor set.
        // Every fixture must pass the same request decoder before row recipes.
        assert!(matches!(
            envelope.decode_validated_kind().unwrap(),
            DormantSandboxRequestKindV1::OperatorRecover(_)
        ));
        let canonical = envelope.encode();
        let digest = Admission::idempotency_digest_v1([3; 16], idempotency);
        let key = Admission::key_from_original_v1([3; 16], digest);
        let data = Admission {
            operation: Admission::operation_id_v1(&key),
            request_scope: [10; 32],
            target: [1; 16],
            node: [2; 16],
            holder: [3; 16],
            project: [4; 16],
            capability: [5; 16],
            channel: [6; 32],
            authorization_revision: [7; 32],
            idempotency_digest: digest,
            original: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(),
                [9; 16],
                accepted_wall,
                10_000_000_000,
            )
            .unwrap(),
            cutoff: 40_000_000_000,
            wall_expiry,
            canonical_request: &canonical,
        };
        let admission = stop_cleanup_admission_transaction_v1(data, idempotency).unwrap();
        let mut state = State::new();
        for member in admission.records() {
            state.insert(
                (member.namespace(), member.key().to_vec()),
                member.value().unwrap().to_vec(),
            );
        }
        if succeeded {
            let clock = RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
                [9; 16],
                110,
                20_000_000_000,
            )
            .unwrap();
            let terminal = closed_cleanup_terminal_transaction_data_v2(
                PublicRecoveryKindV1::StopCleanup,
                data,
                stop_cleanup_operation_v1(data).unwrap(),
                clock,
            )
            .unwrap();
            for member in terminal.records() {
                state.insert(
                    (member.namespace(), member.key().to_vec()),
                    member.value().unwrap().to_vec(),
                );
            }
        }
        Fixture {
            raw: state
                .get(&(RecordNamespace::OperatorRecovery, key.to_vec()))
                .unwrap()
                .clone(),
            state,
            key: key.to_vec(),
            operation: OperationId::from_bytes(data.operation),
            request: data.request_digest_v1(),
        }
    }

    fn observe(fixture: &Fixture, state: &State) -> AdmissionOriginal {
        let index = BTreeMap::new();
        let rows = HistoricalLedgerRowsDataV2::new(state, &index);
        let mut original = AdmissionOriginal::new(&fixture.key, &fixture.raw);
        let _retained = original.observe(
            rows,
            OperationId::from_bytes([1; 16]),
            ProjectId::from_bytes([4; 16]),
        );
        original
    }

    fn superseded(mut fixture: Fixture, wall: i64) -> Fixture {
        let admission = Admission::decode_v1(&fixture.raw).unwrap();
        // The old boot/expiry remain history. This sample supplies only the
        // canonical metadata recipe, never a native completion or fresh loan.
        let clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(),
            [21; 16], wall, 30_000_000_000,
        ).unwrap();
        let terminal = stop_cleanup_superseded_operation_data_v1(
            admission, stop_cleanup_operation_v1(admission).unwrap(), clock,
        ).unwrap();
        fixture.state.insert(
            (RecordNamespace::Operation, fixture.operation.as_bytes().to_vec()),
            aos_sandbox_protocol::domain_ledger::operation::encode_operation_record(terminal),
        );
        fixture
    }

    #[test]
    fn canonical_superseded_history_joins_current_success_without_old_authority() {
        let old = superseded(fixture_with_clock(b"pre-a8-crash", false, 9, 6, 50, 90), 110);
        let current = fixture(b"fresh-current", true);
        let mut state = old.state.clone();
        state.extend(current.state.clone());
        let models = [observe(&old, &state), observe(&current, &state)];

        for model in &models {
            assert!(model.completed().is_ok(), "{:?}", model.failure());
        }
        let selected = select_family(&models, current.operation, current.request).unwrap();

        assert_eq!(selected.current, current.operation);
        assert_eq!(models[0].completed().unwrap().state, OperationState::PermanentlyBlocked);
        assert_eq!(Admission::decode_v1(&old.raw).unwrap().wall_expiry, 90);
        assert_ne!(old.operation, selected.current);
    }

    #[test]
    fn superseded_history_requires_exact_current_target_fence_and_completion_wall() {
        let current = fixture(b"current-success", true);
        for old in [
            superseded(fixture_with_fence(b"foreign-version", false, 8, 6), 110),
            superseded(fixture_with_fence(b"foreign-evidence", false, 9, 7), 110),
            superseded(fixture(b"different-terminal-cut", false), 111),
        ] {
            let mut state = old.state.clone();
            state.extend(current.state.clone());
            let models = [observe(&old, &state), observe(&current, &state)];
            assert!(models[0].completed().is_ok(), "{:?}", models[0].failure());
            assert!(models[1].completed().is_ok(), "{:?}", models[1].failure());
            assert!(select_family(&models, current.operation, current.request).is_err());
        }

        let old = superseded(fixture(b"immutable-old", false), 110);
        let mut changed = old.state.clone();
        changed.get_mut(&(RecordNamespace::OperatorRecovery, old.key.clone())).unwrap().push(0);
        assert!(observe(&old, &changed).completed().is_err());

        let mut extra_transition = old.state.clone();
        let key = (RecordNamespace::Operation, old.operation.as_bytes().to_vec());
        let operation = decode_operation(extra_transition.get(&key).unwrap()).unwrap();
        let public = operation.public_operation().unwrap()
            .advance(OperationState::PermanentlyBlocked, 111).unwrap();
        extra_transition.insert(key,
            aos_sandbox_protocol::domain_ledger::operation::encode_operation_record(
                operation.with_state_and_public_operation(OperationState::PermanentlyBlocked, Some(public))));
        assert!(observe(&old, &extra_transition).completed().is_err());
    }

    #[test]
    fn literal_older_accepted_and_distinct_unique_success_share_the_canonical_family() {
        let old = fixture(b"older-a8-recover", false);
        let current = fixture(b"fresh-current-recover", true);
        let mut state = old.state.clone();
        state.extend(current.state.clone());
        let old_model = observe(&old, &state);
        let current_model = observe(&current, &state);
        let models = [old_model, current_model];

        for model in &models {
            assert!(model.completed().is_ok(), "{:?}", model.failure());
        }
        let selected = select_family(&models, old.operation, old.request).unwrap();

        assert_eq!(selected.old, old.operation);
        assert_eq!(selected.current, current.operation);
        assert_ne!(selected.old, selected.current);
        assert_eq!(
            models[0].completed().unwrap().state,
            OperationState::Accepted
        );
        assert_eq!(
            state.get(&(
                RecordNamespace::Operation,
                old.operation.as_bytes().to_vec()
            )),
            old.state.get(&(
                RecordNamespace::Operation,
                old.operation.as_bytes().to_vec()
            ))
        );
    }

    #[test]
    fn every_immutable_member_and_zero_effect_roster_remain_required() {
        let original = fixture(b"immutable-members", true);
        assert!(observe(&original, &original.state).completed().is_ok());
        let admission = Admission::decode_v1(&original.raw).unwrap();
        let transaction =
            stop_cleanup_admission_transaction_v1(admission, b"immutable-members").unwrap();
        for member in transaction
            .records()
            .iter()
            .filter(|row| row.namespace() != RecordNamespace::Operation)
        {
            let mut changed = original.state.clone();
            changed
                .get_mut(&(member.namespace(), member.key().to_vec()))
                .unwrap()
                .push(0);
            let observed = observe(&original, &changed);
            assert!(observed.completed().is_err());
            assert!(observed.failure().is_some());
        }
        let mut orphan = original.state.clone();
        orphan.insert(
            (
                RecordNamespace::Effect,
                aos_sandbox_protocol::domain_ledger::operation::effect_key(original.operation, 0)
                    .to_vec(),
            ),
            vec![0],
        );
        assert!(observe(&original, &orphan).completed().is_err());
    }

    #[test]
    fn additional_pending_or_multiple_succeeded_candidates_never_become_allowed_ids() {
        let old = fixture(b"a8-reference", false);
        let current = fixture(b"current-success", true);
        let other = fixture(b"other-success", true);
        let pending = fixture(b"unrelated-pending", false);
        let mut state = old.state.clone();
        for fixture in [&current, &other, &pending] {
            state.extend(fixture.state.clone());
        }
        let two_successes = [
            observe(&old, &state),
            observe(&current, &state),
            observe(&other, &state),
        ];
        assert!(two_successes.iter().all(|model| model.completed().is_ok()));
        assert!(select_family(&two_successes, old.operation, old.request).is_err());
        let unrelated_pending = [
            observe(&old, &state),
            observe(&current, &state),
            observe(&pending, &state),
        ];
        assert!(unrelated_pending.iter().all(|model| model.completed().is_ok()));
        assert!(select_family(&unrelated_pending, old.operation, old.request).is_err());
        let models = [observe(&old, &state), observe(&current, &state)];
        assert!(select_family(&models, old.operation, [99; 32]).is_err());
    }
}
