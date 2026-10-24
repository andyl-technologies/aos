//! Joins accepted Create rows to Root's independently read Controller history.
//!
//! The ordinary policy-hold reader and accepted-row validator remain the sole
//! semantic engines. Root prepays their bounded consuming work, retains B and
//! its protected native replay, and parks each returned result before posts.
//! None of these historical comparisons can issue a Controller loan or U.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::controller_policy_hold::{
    ControllerHoldReadbackV1, ControllerPolicyHoldV1, current_readback,
};
use aos_sandbox_protocol::domain_ledger::{
    create_q04_history::{Q04CutIdentityV1, Q04EffectSubgateV1,
        original_rows::accepted_create::AcceptedCreateRowsDataV1},
    transaction::JournalTransaction,
};
#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::transaction::JournalRecord;
use std::error::Error;
use std::mem::size_of;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::{
    create_storage_history::{controller_intent::ControllerIntentBodyDataV1,
        ready::ControllerAdmissionDataV1},
    effect_history::{EffectHistoryDataError, EffectLedgerRecord, decode_effect_with_q04},
    resource_bank::{self as bank, AccountHead, Claim, ClaimCut, ClaimPurpose, ClaimState,
        CoissuanceBinding, ResourceBankDataError, TerminalBinding},
};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Retains full accepted-Create historical comparison DATA and original errors.
///
/// Positive comparison does not establish native replay, protected custody or a role.
#[derive(Default)]
pub struct ControllerCreateAcceptanceDataV1 {
    readback: Option<Result<ControllerHoldReadbackV1, JournalError>>,
    current_effect: Option<Result<(EffectLedgerRecord, Option<Q04EffectSubgateV1>), EffectHistoryDataError>>,
    rows: AcceptedCreateRowsDataV1,
    coissuance: Option<Result<CoissuanceBinding, ResourceBankDataError>>,
    terminal: Option<Result<TerminalBinding, ResourceBankDataError>>,
    head: Option<Result<AccountHead, ResourceBankDataError>>,
    claim: Option<Result<Claim, ResourceBankDataError>>,
    bank: Option<Result<(), ResourceBankDataError>>,
    validation: Option<Result<Option<bank::EnrollmentIdentity>, ResourceBankDataError>>,
    result: Option<Result<(), JournalError>>,
    entered: bool,
    closed: bool,
}

impl ControllerCreateAcceptanceDataV1 {
    /// Runs the full accepted map comparison once and parks its returned result.
    pub fn observe_once(&mut self, state: &State, original: ControllerIntentBodyDataV1<'_>) {
        if self.entered {
            self.closed = true;
            if !matches!(self.result, Some(Err(_))) {
                self.result = Some(Err(JournalError::ProtectedBoundary));
            }
            return;
        }
        self.entered = true;
        self.result = Some(self.compare_inner(state, original));
    }

    fn compare_inner(&mut self, state: &State, original: ControllerIntentBodyDataV1<'_>)
        -> Result<(), JournalError>
    {
        // This same decoder checks all namespace members, the exact phase
        // chain, deterministic transaction IDs, hold release and input origin.
        self.readback = Some(current_readback(state));
        let readback = positive(&self.readback)?;
        let history = readback.q04.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        let identity = &history.identity;
        let last = history.phases.last().ok_or(JournalError::ProtectedBoundary)?;
        if readback.hold.is_none_or(ControllerPolicyHoldV1::is_held)
            || history.phases.len() != 8 || last.phase() != 8
            || identity.operation().as_bytes() != &original.identity.operation
            || identity.project().as_bytes() != &original.identity.project
            || identity.sandbox().as_bytes() != &original.identity.sandbox
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let operation = row(state, RecordNamespace::Operation, identity.operation().as_bytes())?;
        let desired_key = aos_sandbox_protocol::public_api::projection::projection_key(
            aos_sandbox_protocol::public_api::projection::PublicProjectionKindV1::Sandbox,
            identity.sandbox().into_bytes(),
        );
        let desired = row(state, RecordNamespace::DesiredState, &desired_key)?;
        let effect_key = aos_sandbox_protocol::domain_ledger::operation::effect_key(identity.operation(), 0);
        let effect = row(state, RecordNamespace::Effect, &effect_key)?;
        if operation != original.operation || desired != original.desired
            || !state.iter().any(|((namespace, _), bytes)| {
                *namespace == RecordNamespace::Idempotency && bytes.len() == 48
                    && bytes[..32] == original.identity.accepted_request
                    && bytes[32..] == original.identity.operation
            })
            || state.iter().any(|((namespace, key), bytes)| {
                *namespace == RecordNamespace::Effect && bytes.first() == Some(&6)
                    && key.as_slice() != effect_key.as_slice()
            })
        {
            return Err(JournalError::ProtectedBoundary);
        }

        self.current_effect = Some(decode_effect_with_q04(effect));
        let (_, gate) = positive(&self.current_effect)?;
        let gate = gate.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        gate.require_cut_identity(identity)?;
        if gate.status() != 4 || gate.acknowledgement() != last.acknowledgement()
            || gate.historical_consumed_record()?.digest().as_bytes() != &last.bytes()[128..160]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.rows.observe_once(original.operation, original.desired, original.effect,
            original.accepted_context, effect, identity, gate);
        self.rows.require_complete().map_err(|_| JournalError::ProtectedBoundary)?;

        self.validation = Some(bank::validate(state));
        positive(&self.validation)?.as_ref().ok_or(JournalError::ProtectedBoundary)?;
        self.coissuance = Some(CoissuanceBinding::decode(original.coissuance));
        let coissuance = *positive(&self.coissuance)?;
        if !coissuance.matches_q04_cut(identity)
            || !coissuance.matches_specification_bytes_v1(original.specification)
            || coissuance.commitment().map_err(|_| JournalError::ProtectedBoundary)?
                != original.identity.coissuance_binding
        {
            return Err(JournalError::ProtectedBoundary);
        }
        self.bank = Some(coissuance.require_replayed(state));
        positive(&self.bank)?;
        self.terminal = Some(TerminalBinding::decode(original.terminal));
        let terminal = *positive(&self.terminal)?;
        terminal.require_original_coissuance_data_v1(coissuance)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        if bank::terminal_bytes(state, terminal.native_fields().original_id) != Some(original.terminal)
            || terminal.native_fields().names != original.identity.j_names
            || terminal.root_final_data_v1().as_slice() != &last.bytes()[256..288]
        {
            return Err(JournalError::ProtectedBoundary);
        }

        self.head = Some(AccountHead::decode(original.j_head));
        self.claim = Some(Claim::decode(original.j_claim));
        let head = positive(&self.head)?.native_fields();
        let claim = positive(&self.claim)?;
        let fields = claim.native_fields();
        let use_claim = coissuance.native_fields().use_claim.native_fields();
        if claim.operation() != [0; 16]
            || fields.enrollment != head.enrollment || fields.enrollment != use_claim.enrollment
            || fields.account != head.id
            || fields.id != fields.enrollment.account_id(b"controller-create-continuation-intake-v1")
            || fields.account != fields.enrollment.account_id(b"controller")
            || fields.purpose != ClaimPurpose::CreateContinuationIntake
            || fields.state != ClaimState::Committed
            || fields.enrollment.native_fields().boot != original.identity.boot
            || fields.cut != ClaimCut::BootLifetime
            || bank::head_bytes(state, head.id).is_none()
            || bank::claim_bytes(state, fields.id).is_none()
            || state.get(&(RecordNamespace::ControllerResourceReservation, original.j_head_key.to_vec()))
                .map(Vec::as_slice) != bank::head_bytes(state, head.id)
            || state.get(&(RecordNamespace::ControllerResourceReservation, original.j_claim_key.to_vec()))
                .map(Vec::as_slice) != bank::claim_bytes(state, fields.id)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        // Membership of these exact old head/claim bytes belongs to the actual
        // J transaction observer, not final-map equality after highwater growth.
        Ok(())
    }

    /// Checks that the retained historical comparison completed without refusal.
    ///
    /// # Errors
    /// Refuses incomplete, repeated or previously failed comparison.
    pub fn require_complete(&self) -> Result<(), JournalError> {
        if !self.closed && matches!(self.result, Some(Ok(()))) { Ok(()) }
        else { Err(JournalError::ProtectedBoundary) }
    }

    /// Borrows the compared Q04 identity after complete historical comparison.
    ///
    /// # Errors
    /// Refuses incomplete, repeated or previously failed comparison.
    pub fn identity_v1(&self) -> Result<&Q04CutIdentityV1, JournalError> {
        self.require_complete()?;
        positive(&self.readback)?.q04.as_ref().map(|history| &history.identity)
            .ok_or(JournalError::ProtectedBoundary)
    }

    /// Copies the compared original terminal digest after complete comparison.
    ///
    /// # Errors
    /// Refuses incomplete, repeated or previously failed comparison.
    pub fn root_final_v1(&self) -> Result<[u8; 32], JournalError> {
        self.require_complete()?;
        Ok(positive(&self.terminal)?.root_final_data_v1())
    }

    /// Borrows the first retained historical decoder, comparison or bank cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.readback).or_else(|| cause(&self.current_effect))
            .or_else(|| self.rows.failure()).or_else(|| cause(&self.validation))
            .or_else(|| cause(&self.coissuance))
            .or_else(|| cause(&self.bank)).or_else(|| cause(&self.terminal))
            .or_else(|| cause(&self.head)).or_else(|| cause(&self.claim))
            .or_else(|| cause(&self.result))
    }

    // The surrounding State pays inline storage. This supplier covers dominant
    // consuming decoder/model/canonical buffers using the actual encoded cut.
    // Scalar controls are not resident namespace metadata entries.
    /// Quotes the original consuming model and canonical-buffer demand.
    ///
    /// # Errors
    /// Returns JournalTooLarge when the original geometry or conversion overflows.
    pub fn additional_receiving_demand_v1(encoded_bytes: u64)
        -> Result<ResourceVector, JournalError>
    {
        let invalid = || JournalError::JournalTooLarge;
        let repeated_width = size_of::<aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::accepted_create::CreateSandboxRequest>()
            .checked_add(size_of::<aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::accepted_create::Sandbox>())
            .and_then(|width| width.checked_add(size_of::<aos_sandbox_protocol::public_api::projection::PublicProjectionRecordV1>()))
            .and_then(|width| width.checked_add(size_of::<EffectLedgerRecord>()))
            .and_then(|width| width.checked_add(
                size_of::<aos_sandbox_protocol::policy_data::RetainedPublisherCompilerOriginV3>()
            ))
            .and_then(|width| width.checked_add(size_of::<(String, Vec<u8>, [usize; 4])>()))
            .ok_or_else(invalid)?;
        let schema = aos_sandbox_protocol::domain_ledger::create_q04_history::original_rows::accepted_create::protobuf_carriers_v1(
            encoded_bytes, u64::try_from(repeated_width).map_err(|_| invalid())?,
        ).map_err(|_| invalid())?;
        // Separate live planes cover Effect canonical/model validation, public
        // context and request validation, routed request/command construction,
        // Desired checked-resource construction, and retained compiler origin.
        let bytes = schema.checked_mul(9)
            .and_then(|bytes| encoded_bytes.checked_mul(32)?.checked_add(bytes))
            .ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, bytes)
            .with(D::OutputBytes, encoded_bytes.checked_mul(16).ok_or_else(invalid)?))
    }
}

fn row<'a>(state: &'a State, namespace: RecordNamespace, key: &[u8]) -> Result<&'a [u8], JournalError> {
    state.get(&(namespace, key.to_vec())).map(Vec::as_slice).ok_or(JournalError::ProtectedBoundary)
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    result.as_ref().and_then(|result| result.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

/// Keeps the actual observer results after its temporary borrowed facade ends.
/// Retains CPU COMMIT/EOF comparison progress without native authority.
#[derive(Default)]
pub struct ControllerAcceptedHistoryProgressDataV1 {
    bank: Option<Result<(), ResourceBankDataError>>,
    result: Option<Result<(), JournalError>>,
    j_matched: bool,
    admission_matched: bool,
    admission: Option<Result<(), ResourceBankDataError>>,
    complete: bool,
}

impl ControllerAcceptedHistoryProgressDataV1 {
    /// Checks that the retained historical comparison completed without refusal.
    ///
    /// # Errors
    /// Refuses incomplete, repeated or previously failed comparison.
    pub fn require_complete(&self) -> Result<(), JournalError> {
        if self.complete && self.j_matched && self.admission_matched
            && matches!(self.admission, Some(Ok(()))) && matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else { Err(JournalError::ProtectedBoundary) }
    }

    /// Borrows the first retained historical decoder, comparison or bank cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.bank).or_else(|| cause(&self.admission)).or_else(|| cause(&self.result))
    }
}

#[derive(Clone, Copy)]
enum AdmissionCurrentHeadV1<'data> {
    Initial,
    UseReserved(aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>),
    UseCommitted(aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>),
}

/// Borrows one historical bank observer, original admission DATA and progress.
///
/// Callers must supply COMMIT/EOF events from their genuine native reader; this
/// public DATA observer cannot create or replace that reader or its admission.
pub struct ControllerAcceptedHistoryObserverDataV1<'state, 'data, 'progress> {
    bank: bank::PhysicalHistory<'state>,
    current_head: AdmissionCurrentHeadV1<'data>,
    original: ControllerIntentBodyDataV1<'data>,
    admission: ControllerAdmissionDataV1<'data>,
    state: &'state State,
    progress: &'progress mut ControllerAcceptedHistoryProgressDataV1,
}

impl<'state, 'data, 'progress> ControllerAcceptedHistoryObserverDataV1<'state, 'data, 'progress> {
    /// Creates a CPU observer over the supplied historical bank map and original DATA.
    pub fn new(
        state: &'state State,
        original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        progress: &'progress mut ControllerAcceptedHistoryProgressDataV1,
    ) -> Option<Self> {
        Some(Self { bank: bank::PhysicalHistory::new(state)?, current_head: AdmissionCurrentHeadV1::Initial,
            original, admission, state, progress })
    }

    /// Creates the reserved-use alternative over the same historical bank recipe.
    pub fn new_reserved(
        state: &'state State,
        original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        reserved: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'progress mut ControllerAcceptedHistoryProgressDataV1,
    ) -> Option<Self> {
        let mut observer = Self::new(state, original, admission, progress)?;
        observer.current_head = AdmissionCurrentHeadV1::UseReserved(reserved);
        Some(observer)
    }

    /// Creates the committed-use alternative over the same historical bank recipe.
    pub fn new_committed(
        state: &'state State, original: ControllerIntentBodyDataV1<'data>,
        admission: ControllerAdmissionDataV1<'data>,
        reserved: aos_sandbox_protocol::domain_ledger::create_storage_history::use_reserved::UseReservedBodyDataV1<'data>,
        progress: &'progress mut ControllerAcceptedHistoryProgressDataV1,
    ) -> Option<Self> {
        let mut observer = Self::new(state, original, admission, progress)?;
        observer.current_head = AdmissionCurrentHeadV1::UseCommitted(reserved);
        Some(observer)
    }

    /// Borrows the first cause retained by this same historical observer.
    ///
    /// This diagnostic performs no comparison, progress mutation or native work.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.progress.failure()
    }

    /// Checks one actual COMMIT event against the original J pair and bank history.
    ///
    /// # Errors
    /// Preserves exact J membership/position refusal and the bank observer cause.
    pub fn observe(
        &mut self, transaction: &JournalTransaction, begin: u64, commit: u64,
        before_end: u64, after_end: u64,
    ) -> Result<(), JournalError> {
        if self.progress.complete || self.progress.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.progress.result = Some((|| {
            if transaction.id() == &self.original.identity.j_transaction {
                if self.progress.j_matched { return Err(JournalError::ProtectedBoundary); }
                require_original_j_transaction(self.original, transaction, begin, commit, after_end)?;
                self.progress.j_matched = true;
            }
            if admission_pair_matches(self.original, self.admission, transaction) {
                if self.progress.admission_matched { return Err(JournalError::ProtectedBoundary); }
                self.progress.admission_matched = true;
            }
            self.progress.bank = Some(self.bank.observe(transaction, begin, commit, before_end, after_end));
            positive(&self.progress.bank).map(|_| ())
        })());
        positive(&self.progress.result).map(|_| ())
    }

    /// Finishes EOF comparison using the original recorded names DATA.
    ///
    /// # Errors
    /// Refuses missing original members or a failed bank, name or admission comparison.
    pub fn finish_original_names(
        &mut self, ids: &std::collections::BTreeSet<[u8; 16]>,
    ) -> Result<(), JournalError> {
        self.finish(ids, self.original.identity.j_names)
    }

    /// Finishes atomic membership, final bank map and current admission comparison.
    ///
    /// # Errors
    /// Refuses missing original members or a failed bank, name or admission comparison.
    pub fn finish(
        &mut self, ids: &std::collections::BTreeSet<[u8; 16]>,
        names: aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1,
    ) -> Result<(), JournalError> {
        if self.progress.complete || self.progress.failure().is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.progress.result = Some((|| {
            if !self.progress.j_matched || !self.progress.admission_matched { return Err(JournalError::ProtectedBoundary); }
            self.progress.bank = Some(self.bank.finish(ids, names));
            positive(&self.progress.bank)?;
            self.progress.admission = Some(require_admission_accounts_inner(self.state, self.original, self.admission, self.current_head));
            positive(&self.progress.admission).map(|_| ())
        })());
        positive(&self.progress.result)?;
        self.progress.complete = true;
        Ok(())
    }
}

// The B snapshot can precede later valid J highwater growth. Require its
// actual atomic pair in this SAME validated native history, rather than falsely
// equating old bytes with the final Controller head. No new parser is used.
fn admission_pair_matches(original: ControllerIntentBodyDataV1<'_>,
    admission: ControllerAdmissionDataV1<'_>, transaction: &JournalTransaction,
) -> bool {
    let records = transaction.records();
    records.len() == 2
        && records[0].namespace() == RecordNamespace::ControllerResourceReservation
        && records[1].namespace() == RecordNamespace::ControllerResourceReservation
        && records[0].key() == original.j_head_key
        && records[0].value() == Some(admission.controller)
        && records[1].key() == original.j_claim_key
        && records[1].value() == Some(admission.intake)
}

fn require_admission_accounts(state: &State, original: ControllerIntentBodyDataV1<'_>,
    admission: ControllerAdmissionDataV1<'_>,
) -> Result<(), ResourceBankDataError> {
    require_admission_accounts_inner(state, original, admission, AdmissionCurrentHeadV1::Initial)
}

fn require_admission_accounts_inner(state: &State, original: ControllerIntentBodyDataV1<'_>,
    admission: ControllerAdmissionDataV1<'_>, current_head: AdmissionCurrentHeadV1<'_>,
) -> Result<(), ResourceBankDataError> {
    let coissuance = CoissuanceBinding::decode(original.coissuance)?;
    let child_use = coissuance.native_fields().use_claim.native_fields();
    let enrollment = child_use.enrollment;
    for (bytes, id, kind) in [
        (admission.controller, enrollment.account_id(b"controller"), bank::AccountKind::Controller),
        (admission.sandbox, child_use.account, bank::AccountKind::Sandbox),
    ] {
        let fields = AccountHead::decode(bytes)?.native_fields();
        if fields.id != id || fields.enrollment != enrollment || fields.kind != kind {
            return Err(ResourceBankDataError::Conflict);
        }
    }
    // The Sandbox head is unchanged until the forthcoming genuine U. Its
    // complete current row must agree; Controller/J snapshots were matched at
    // their actual historical atomic pair above. PhysicalHistory independently
    // validates every intervening bank transition and the complete final map.
    match current_head {
        AdmissionCurrentHeadV1::Initial => {
            if bank::head_bytes(state, child_use.account) != Some(admission.sandbox) {
                return Err(ResourceBankDataError::Conflict);
            }
        }
        AdmissionCurrentHeadV1::UseReserved(reserved) => {
            let claim = Claim::decode(reserved.claim)?;
            let fields = claim.native_fields();
            let binding = bank::CreateStorageUseBindingV1::decode(reserved.binding)?;
            let exact = bank::CreateStorageUseBindingV1::new(coissuance,
                binding.use_authorized_checksum(), reserved.root_validated, claim)?;
            if exact.encode()?.as_slice() != reserved.binding
                || fields.state != ClaimState::Reserved
                || bank::head_bytes(state, child_use.account) != Some(reserved.head.as_slice())
                || bank::claim_bytes(state, fields.id) != Some(reserved.claim.as_slice())
                || binding.reserve_transaction_id()? != reserved.transaction
            { return Err(ResourceBankDataError::Conflict); }
        }
        AdmissionCurrentHeadV1::UseCommitted(reserved) => {
            let claim = Claim::decode(reserved.claim)?;
            let binding = bank::CreateStorageUseBindingV1::decode(reserved.binding)?;
            let exact = bank::CreateStorageUseBindingV1::new(coissuance,
                binding.use_authorized_checksum(), reserved.root_validated, claim)?;
            if exact.encode()?.as_slice() != reserved.binding
                || binding.reserve_transaction_id()? != reserved.transaction
            { return Err(ResourceBankDataError::Conflict); }
            // The SAME bank validator requires immutable original/binding,
            // historical terminal, inherited whole claim and committed head.
            binding.committed_replayed_pair_v1(state, claim)?;
        }

    }
    let claim = Claim::decode(admission.intake)?;
    let fields = claim.native_fields();
    if fields.enrollment != enrollment
        || fields.id != enrollment.account_id(b"controller-create-continuation-intake-v1")
        || fields.account != enrollment.account_id(b"controller")
        || fields.purpose != ClaimPurpose::CreateContinuationIntake
        || fields.state != ClaimState::Committed
    { return Err(ResourceBankDataError::Conflict); }
    Ok(())
}

fn require_original_j_transaction(
    original: ControllerIntentBodyDataV1<'_>, transaction: &JournalTransaction,
    begin: u64, commit: u64, after_end: u64,
) -> Result<(), JournalError> {
    let records = transaction.records();
    if records.len() != 2 || transaction.id() != &original.identity.j_transaction
        || commit != original.identity.j_commit || after_end != original.identity.j_end
        || begin.checked_add(3) != Some(commit)
        || records[0].namespace() != RecordNamespace::ControllerResourceReservation
        || records[1].namespace() != RecordNamespace::ControllerResourceReservation
        || records[0].key() != original.j_head_key || records[0].value() != Some(original.j_head)
        || records[1].key() != original.j_claim_key || records[1].value() != Some(original.j_claim)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::controller_intent::ControllerIntentIdentityDataV1;
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

    fn original() -> ControllerIntentBodyDataV1<'static> {
        ControllerIntentBodyDataV1 {
            identity: ControllerIntentIdentityDataV1 {
                lane: [1; 16], operation: [2; 16], project: [3; 16], sandbox: [4; 16],
                accepted_request: [5; 32], coissuance_binding: [6; 32], controller_nonce: [7; 16],
                boot: [8; 16], started: 10, cutoff: 20, j_transaction: [9; 16],
                j_names: ProtectedJournalNamesV1::from_bytes(&[1; 48]).unwrap(),
                j_commit: 24, j_end: 2048,
            },
            accepted_context: b"context", operation: b"operation", desired: b"desired", effect: b"effect",
            specification: b"specification", coissuance: b"coissuance", terminal: b"terminal",
            j_head_key: b"head", j_head: b"original-head", j_claim_key: b"claim", j_claim: b"original-claim",
        }
    }

    fn transaction(original: ControllerIntentBodyDataV1<'_>) -> JournalTransaction {
        JournalTransaction::new(original.identity.j_transaction, vec![
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                original.j_head_key.to_vec(), original.j_head.to_vec()),
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                original.j_claim_key.to_vec(), original.j_claim.to_vec()),
        ]).unwrap()
    }

    #[test]
    fn historical_admission_requires_one_ordered_native_pair() {
        // Opaque comparison DATA only: these values cannot create a bank or R.
        let original = original();
        let admission = ControllerAdmissionDataV1 {
            controller: b"historical-controller-head", sandbox: b"unchanged-child",
            intake: b"historical-J-highwater",
        };
        let historical = JournalTransaction::new([12; 16], vec![
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                original.j_head_key.to_vec(), admission.controller.to_vec()),
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                original.j_claim_key.to_vec(), admission.intake.to_vec()),
        ]).unwrap();
        let later = JournalTransaction::new([13; 16], vec![
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                original.j_head_key.to_vec(), b"later-controller-head".to_vec()),
            JournalRecord::put(RecordNamespace::ControllerResourceReservation,
                original.j_claim_key.to_vec(), b"later-J-highwater".to_vec()),
        ]).unwrap();

        assert!(admission_pair_matches(original, admission, &historical));
        assert!(!admission_pair_matches(original, admission, &later));
        let reversed = JournalTransaction::new([14; 16],
            historical.records().iter().rev().cloned().collect()).unwrap();
        assert!(!admission_pair_matches(original, admission, &reversed));
        let mixed = ControllerAdmissionDataV1 { intake: b"later-J-highwater", ..admission };
        assert!(!admission_pair_matches(original, mixed, &historical));
        assert!(!admission_pair_matches(original, mixed, &later));
    }

    #[test]
    fn original_j_requires_whole_ordered_members_and_the_exact_native_position() {
        // Native comparison DATA only; these opaque values do not construct a
        // bank, accepted Create, protected reader, R original or use authority.
        let original = original();
        let expected = transaction(original);
        assert!(require_original_j_transaction(original, &expected, 21, 24, 2048).is_ok());
        assert!(require_original_j_transaction(original, &expected, 20, 24, 2048).is_err());
        assert!(require_original_j_transaction(original, &expected, 21, 24, 2049).is_err());
        let mut changed = original;
        changed.j_claim = b"newer-current-claim";
        assert!(require_original_j_transaction(original, &transaction(changed), 21, 24, 2048).is_err());
        let reversed = JournalTransaction::new(original.identity.j_transaction,
            expected.records().iter().rev().cloned().collect()).unwrap();
        assert!(require_original_j_transaction(original, &reversed, 21, 24, 2048).is_err());
    }

    #[test]
    fn refused_j_member_keeps_its_original_error_and_cannot_reenter_successfully() {
        let original = original();
        let mut state = State::new();
        // Presence selects the shared terminal observer; its malformed body is
        // never decoded because exact J member comparison refuses first.
        state.insert((RecordNamespace::ControllerResourceReservation, vec![b't']), vec![0]);
        let mut progress = ControllerAcceptedHistoryProgressDataV1::default();
        {
            let mut observer = ControllerAcceptedHistoryObserverDataV1::new(&state, original, ControllerAdmissionDataV1 {
                controller: original.j_head, sandbox: b"child", intake: original.j_claim,
            }, &mut progress).unwrap();
            let mut changed = original;
            changed.j_head = b"wrong-head";
            assert!(observer.observe(&transaction(changed), 21, 24, 1000, 2048).is_err());
            assert!(observer.observe(&transaction(original), 21, 24, 1000, 2048).is_err());
        }
        assert!(progress.failure().is_some());
        assert!(progress.bank.is_none());
        assert!(!progress.j_matched);
        assert!(progress.require_complete().is_err());
    }
}

/// Quotes changed mechanical Result/error projections at existing upper callers.
///
/// The generic E is the actual caller error type, never a supplied owner or payer.
#[must_use]
pub fn fixed_interface_control_bytes_v1<E>() -> Option<usize> {
    let canonical = size_of::<Result<(), JournalError>>().checked_mul(9)?;
    let projection = size_of::<JournalError>().checked_mul(9)?;
    let upper = size_of::<Result<(), E>>().checked_mul(9)?;
    let cause = size_of::<E>().checked_mul(9)?;
    let identity = size_of::<Result<&Q04CutIdentityV1, JournalError>>().checked_mul(3)?;
    let terminal = size_of::<Result<[u8; 32], JournalError>>().checked_mul(3)?;
    let demand = size_of::<Result<ResourceVector, JournalError>>().checked_mul(3)?;
    let row_projection = size_of::<aos_sandbox_protocol::domain_ledger::create_q04_history::
        original_rows::Q04OriginalRowsDataErrorV1>().checked_mul(9)?;
    let row_errors = size_of::<aos_sandbox_protocol::domain_ledger::create_q04_history::
        original_rows::accepted_create::AcceptedCreateRowsDataErrorV1>().checked_mul(12)?;
    let supplier = size_of::<Option<usize>>().checked_mul(3)?;
    canonical.checked_add(projection)?
        .checked_add(upper)?
        .checked_add(cause)?
        .checked_add(identity)?
        .checked_add(terminal)?
        .checked_add(demand)?
        .checked_add(row_projection)?
        .checked_add(row_errors)?
        .checked_add(supplier)
}
