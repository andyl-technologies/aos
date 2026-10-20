//! Controller-wide durable custody for one closed policy-binding proposal.
//!
//! ```text
//! AOSCTH01 | version=1 | phase=held|released | reserved[5]=0 |
//! operation[16] | sandbox[16] | source[32] | binding[32] | epoch[8] |
//! SHA-256[32]
//! AOSQ8A01 | version=1 | state=terminal-prepared | reserved[5]=0 |
//! operation[16] | sandbox[16] | source[32] | binding[32] | epoch[8] |
//! exact-Root-terminal-digest[32] | SHA-256[32]
//! AOSQ8K01 | version=1 | state=acknowledged-no-Apply | reserved[5]=0 |
//! AOSQ8A01[184] | accepted-generation[8] | effect-transaction[16] |
//! consumed-AOSPCP02-digest[32] | Cache-quota-digest[32] | SHA-256[32]
//! AOSQ8R01 | version=1 | reserved[6]=0 | AOSPC88A[332] | SHA-256[32]
//! ```
//!
//! The hold freezes ordinary Controller mutations across crash and reopen.
//! Only exact private no-Apply acknowledgment and release transitions can
//! write while held. Neither freezes other owners nor authorizes public Create,
//! policy publication, or Apply. The AOSQ8F01 and AOSQ8S01 DATA codecs are shared with
//! LedgerReplay; their mutation exceptions remain private to this owner.

use aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1;
use aos_sandbox_protocol::domain_ledger::cache_policy_hold::CachePolicyHoldV1;

use crate::journal::{CacheMutationGateV1, PreflightTransactionViewV1};
use crate::journal::semantic_append::{AppendScope, PreflightScope};

use std::collections::BTreeMap;

use aos_sandbox_core::{ObjectDigest, OperationId, SandboxId};
use sha2::{Digest as _, Sha256};

use crate::policy_compiler::{ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1, RootV8EffectAckV1};

use super::{
    Journal,
    JournalError,
    JournalRecord,
    JournalTransaction,
    RecordNamespace,
};

#[cfg(target_os = "linux")]
use crate::policy_compiler::create_q04::{
    CONTROLLER_IDENTITY_KEY, CONTROLLER_PHASE_PREFIX, Q04CutIdentityV1,
    CreateQ04ErrorV1, Q04EffectSubgateV1, Q04PhaseOwnerV1, Q04PhaseRecordV1,
    Q04RootDecisionV1, Q04TransactionOwnerV1,
};

#[cfg(target_os = "linux")]
mod create_storage_acceptance;

#[cfg(target_os = "linux")]
pub(crate) use create_storage_acceptance::{
    RootControllerCreateAcceptanceOriginalsV1, RootControllerAcceptedNativeProgressV1,
    RootControllerAcceptedNativeV1,
};

use v8_pre_release_floor::{
    KEY as V8_FLOOR_KEY, RECORD_BYTES as V8_FLOOR_RECORD_BYTES,
    TRANSACTION_DOMAIN as V8_FLOOR_TRANSACTION_DOMAIN,
};

use aos_sandbox_ledger_replay::controller_policy_hold as canonical;
use canonical::ControllerHoldReadbackV1;
#[cfg(target_os = "linux")]
pub(crate) use canonical::ControllerQ04HistoryV1;
use canonical::{
    ACK_KEY, CHECKSUM_DOMAIN, KEY, MAGIC, RECORD_BYTES, TRANSACTION_DOMAIN, V8_ACK_CHECKSUM_DOMAIN,
    V8_ACK_KEY, V8_ACK_MAGIC, V8_ACK_RECORD_BYTES, V8_ACK_TRANSACTION_DOMAIN,
    V8_ATTEMPT_CHECKSUM_DOMAIN, V8_ATTEMPT_KEY, V8_ATTEMPT_MAGIC, V8_ATTEMPT_RECORD_BYTES,
    V8_ATTEMPT_TRANSACTION_DOMAIN, V8_ROOT_RECEIPT_CHECKSUM_DOMAIN, V8_ROOT_RECEIPT_KEY,
    V8_ROOT_RECEIPT_MAGIC, V8_ROOT_RECEIPT_RECORD_BYTES, V8_ROOT_RECEIPT_TRANSACTION_DOMAIN,
    V8_SETTLEMENT_CHECKSUM_DOMAIN, V8_SETTLEMENT_KEY, V8_SETTLEMENT_MAGIC,
    V8_SETTLEMENT_RECORD_BYTES, V8_SETTLEMENT_TRANSACTION_DOMAIN,
};
pub use canonical::{
    ControllerPolicyHoldV1, ControllerPolicyV8AttemptV1, ControllerPolicyV8EffectAckV1,
};
pub(crate) use canonical::{
    ControllerPolicyV8PreReleaseFloorV1, ControllerPolicyV8ReleaseEvidenceV1,
    ControllerPolicyV8SettlementV1,
};
use canonical::{v8_pre_release_floor, v8_settlement};
mod data_errors;

fn current(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyHoldV1>, JournalError> {
    canonical::current(state).map_err(JournalError::from)
}

fn current_readback(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<ControllerHoldReadbackV1, JournalError> {
    canonical::current_readback(state).map_err(JournalError::from)
}

// Old private hold transitions are not a Q04 waiver. Check this even when
// they select the existing policy-hold transition flag; only the new named
// closed action may later cross this purpose boundary.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_ordinary_boundary(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    canonical::require_q04_ordinary_boundary(state, transaction).map_err(JournalError::from)
}

// This exception borrows the actual moved Q04 child and its whole Results.
// It cannot select any policy phase, Effect change or ordinary bank mutation.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_terminal_bank_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    terminal: &crate::controller_resource_reservation::Q04TerminalBankAppendV1<'_>,
) -> Result<(), JournalError> {
    terminal.require_current(state, transaction)?;
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::Terminal(terminal))
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_create_intake_bank_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    intake: &crate::controller_resource_reservation::CreateIntakeBankAppendV1<'_>,
) -> Result<(), JournalError> {
    intake.require_current(state, transaction)?;
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::CreateIntake(intake))
}

// The exact same cleared Q04 join admits only the genuine completed Root
// authorization and funded U reservation. It does not waive ordinary guards.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_create_storage_use_bank_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    original: &crate::controller_resource_reservation::CreateStorageUseBankAppendV1<'_>,
) -> Result<(), JournalError> {
    original.require_current(state, transaction)?;
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::CreateStorageUse(original))
}

// The genuine C receiver and exact Core recipe already checked the complete
// candidate rows. Reuse the same sole released-hold/eight-phase/gate validator.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_provisioning_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    original: &crate::reconciler::provisioning::ProvisioningAppendLoanV1<'_>,
) -> Result<(), JournalError> {
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::Provisioning(original))
}

// Only the real ACK-dependent terminal destination admits the public CAS.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_create_stopped_terminal_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    original: &super::create_stopped_terminal::CreateStoppedControllerTerminalAppendLoanV1<'_, '_>,
) -> Result<(), JournalError> {
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::CreateStoppedTerminal(original))
}

// A genuine Completing/Applied pre-ACK context admits only its exact parent
// Effect replacement; the eight-phase released Q04 history is unchanged.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_create_stopped_pre_ack_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    original: &super::create_stopped_pre_ack::CreateStoppedControllerPreAckAppendLoanV1<'_>,
) -> Result<(), JournalError> {
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::CreateStoppedPreAck(original))
}

// This later history transition borrows the SAME actual parent and successful
// J return. It changes only the exact first namespace81 record/head pair and
// preserves all eight old Q04 phases, released hold and consumed Effect gate.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_create_storage_history_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    original: &crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'_, '_>,
) -> Result<(), JournalError> {
    original.require_controller_history_successor(state, transaction)?;
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::History(original))
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_operator_recover_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    original: &super::operator_recover_floor::OperatorRecoverAppendLoanV1<'_>,
) -> Result<(), JournalError> {
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::OperatorRecover(original))
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_delete_admission_successor_v3(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    original: &dyn super::delete_admission::DeleteAdmissionOriginalV3,
) -> Result<(), JournalError> {
    require_q04_cleared_bank_successor(state, Q04ClearedSuccessorV1::DeleteAdmission(original))
}

#[cfg(target_os = "linux")]
enum Q04ClearedSuccessorV1<'borrow, 'owner, 'original> {
    DeleteAdmission(&'borrow dyn super::delete_admission::DeleteAdmissionOriginalV3),
    OperatorRecover(&'borrow super::operator_recover_floor::OperatorRecoverAppendLoanV1<'owner>),
    Terminal(&'borrow crate::controller_resource_reservation::Q04TerminalBankAppendV1<'owner>),
    CreateIntake(&'borrow crate::controller_resource_reservation::CreateIntakeBankAppendV1<'owner>),
    CreateStorageUse(&'borrow crate::controller_resource_reservation::CreateStorageUseBankAppendV1<'owner>),
    History(&'borrow crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'owner, 'original>),
    Provisioning(&'borrow crate::reconciler::provisioning::ProvisioningAppendLoanV1<'owner>),
    CreateStoppedTerminal(&'borrow super::create_stopped_terminal::CreateStoppedControllerTerminalAppendLoanV1<'owner, 'original>),
    CreateStoppedPreAck(&'borrow super::create_stopped_pre_ack::CreateStoppedControllerPreAckAppendLoanV1<'owner>),
}

#[cfg(target_os = "linux")]
fn require_q04_cleared_bank_successor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    original: Q04ClearedSuccessorV1<'_, '_, '_>,
) -> Result<(), JournalError> {
    let readback = current_readback(state)?;
    let history = readback.q04.ok_or(JournalError::ProtectedBoundary)?;
    let identity_matches = match original {
        Q04ClearedSuccessorV1::DeleteAdmission(original) => original.matches_identity_v3(&history.identity),
        Q04ClearedSuccessorV1::OperatorRecover(original) => original.matches_identity_v1(&history.identity),
        Q04ClearedSuccessorV1::Terminal(original) => original.matches_identity(&history.identity),
        Q04ClearedSuccessorV1::CreateIntake(original) => original.matches_identity(&history.identity),
        Q04ClearedSuccessorV1::CreateStorageUse(original) => original.matches_identity(&history.identity),
        Q04ClearedSuccessorV1::History(original) => original.matches_identity(&history.identity),
        Q04ClearedSuccessorV1::Provisioning(original) => original.matches_identity_v1(&history.identity, state),
        Q04ClearedSuccessorV1::CreateStoppedTerminal(original) => original.matches_identity_v1(&history.identity),
        Q04ClearedSuccessorV1::CreateStoppedPreAck(original) => original.matches_identity_v1(&history.identity),
    };
    if readback.hold.is_none_or(ControllerPolicyHoldV1::is_held)
        || history.phases.len() != 8
        || history.phases.last().is_none_or(|phase| phase.phase() != 8)
        || !identity_matches
    {
        return Err(JournalError::ProtectedBoundary);
    }

    let key = aos_sandbox_protocol::domain_ledger::operation::effect_key(
        history.identity.operation(),
        0,
    );
    let bytes = state
        .get(&(RecordNamespace::Effect, key.to_vec()))
        .ok_or(JournalError::ProtectedBoundary)?;
    let (_, gate) = aos_sandbox_protocol::domain_ledger::effect_history::decode_effect_with_q04(bytes)
        .map_err(crate::reconciler::ReconcilerError::from)
        .map_err(|cause| JournalError::Q04ControllerLedger(Box::new(cause)))?;
    let gate = gate.ok_or(JournalError::ProtectedBoundary)?;
    gate.require_cut_identity(&history.identity)?;
    let last = history.phases.last().ok_or(JournalError::ProtectedBoundary)?;
    if gate.status() != 4
        || gate.acknowledgement() != last.acknowledgement()
        || gate.historical_consumed_record()?.digest().as_bytes() != &last.bytes()[128..160]
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Retains one closed native recipe, never a currentness or commit permit.
///
/// Only the private installed Q04 caller may combine it with the same real
/// Controller writer and original Root/Source/Cache/clock loans. Preflight
/// validates recipe DATA; every append repeats full original admission.
#[cfg(target_os = "linux")]
pub(crate) struct ControllerQ04TransitionV1<'cut> {
    ledger: &'cut crate::reconciler::OriginalQ04ControllerLedgerV1,
    identity: &'cut Q04CutIdentityV1,
    phase: &'cut Q04PhaseRecordV1,
    decision: Option<&'cut Q04RootDecisionV1>,
    gate: Option<&'cut Q04EffectSubgateV1>,
    resource: Option<&'cut crate::controller_resource_reservation::Q04ResourceTransferV1>,
    transaction: JournalTransaction,
}

#[cfg(target_os = "linux")]
impl<'cut> ControllerQ04TransitionV1<'cut> {
    pub(crate) fn recipe(
        ledger: &'cut crate::reconciler::OriginalQ04ControllerLedgerV1,
        identity: &'cut Q04CutIdentityV1,
        phase: &'cut Q04PhaseRecordV1,
        decision: Option<&'cut Q04RootDecisionV1>,
        gate: Option<&'cut Q04EffectSubgateV1>,
        resource: Option<&'cut crate::controller_resource_reservation::Q04ResourceTransferV1>,
    ) -> Result<Self, CreateQ04ErrorV1> {
        ledger.require_identity(identity)?;
        Q04PhaseRecordV1::decode(Q04PhaseOwnerV1::Controller, phase.bytes(), identity)?;
        let number = phase.phase();
        let held = ControllerPolicyHoldV1::new(
            identity.operation(), identity.sandbox(), ledger.source_commitment(),
            identity.binding(), identity.epoch(),
        )?;
        if phase.bytes()[288..320] != *held.record_digest()?.as_bytes()
            || phase.bytes()[512..544] != *identity.before_controller_rows().as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if number >= 2 {
            let decision = decision.ok_or(CreateQ04ErrorV1::ChangedCut)?;
            Q04RootDecisionV1::decode(decision.bytes(), identity)?;
            if phase.bytes()[96..128] != *decision.digest().as_bytes()
                || phase.bytes()[352..384] != decision.bytes()[216..248]
                || phase.bytes()[416..448] != decision.bytes()[248..280]
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        } else if decision.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        let writes_effect = matches!(number, 2 | 5 | 7 | 8);
        if gate.is_some() != writes_effect {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if let Some(gate) = gate {
            gate.require_identity(identity, decision.ok_or(CreateQ04ErrorV1::ChangedCut)?)?;
            if gate.historical_consumed_record()?.digest().as_bytes() != &phase.bytes()[128..160]
                || gate.status() != match number { 2 => 1, 5 => 2, 7 => 3, 8 => 4, _ => 0 }
                || (number != 2 && gate.acknowledgement() != phase.acknowledgement())
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }

        let mut records = Vec::new();
        records.try_reserve_exact(match number { 1 | 5 => 3, 2 | 7 | 8 => 2, _ => 1 })?;
        if number == 1 || number == 5 {
            let row = if number == 1 { held } else { ControllerPolicyHoldV1 { held: false, ..held } };
            if number == 5 && phase.bytes()[320..352] != *row.record_digest()?.as_bytes() {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            records.push(JournalRecord::put(
                RecordNamespace::ControllerPolicyHold, KEY.to_vec(), row.encode()?.to_vec(),
            ));
        }
        if number == 1 {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerPolicyHold, CONTROLLER_IDENTITY_KEY.to_vec(),
                identity.bytes().to_vec(),
            ));
        }
        if let Some(gate) = gate {
            records.push(ledger.effect_record(gate)?);
        }
        let mut phase_key = CONTROLLER_PHASE_PREFIX.to_vec();
        phase_key.push(number);
        records.push(JournalRecord::put(
            RecordNamespace::ControllerPolicyHold, phase_key, phase.bytes().to_vec(),
        ));
        let resource = if number == 1 { resource } else { None };
        if let Some(resource) = resource {
            resource.append_records(&mut records)?;
        }
        let predecessor = if number == 1 {
            identity.before_controller_rows()
        } else {
            ObjectDigest::from_bytes(phase.bytes()[64..96].try_into()
                .map_err(|_| JournalError::ProtectedBoundary)?)
        };
        let transaction = JournalTransaction::new(
            Q04TransactionOwnerV1::Controller.transaction_id(identity, number, predecessor)?,
            records,
        )?;
        if transaction.id() != &phase.native_transaction_id() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(Self { ledger, identity, phase, decision, gate, resource, transaction })
    }

    pub(crate) fn transaction(&self) -> &JournalTransaction {
        &self.transaction
    }

    pub(crate) fn ledger(&self) -> &crate::reconciler::OriginalQ04ControllerLedgerV1 {
        self.ledger
    }

    pub(crate) fn identity(&self) -> &Q04CutIdentityV1 {
        self.identity
    }

    pub(crate) fn phase_record(&self) -> &Q04PhaseRecordV1 {
        self.phase
    }

    pub(crate) fn phase_number(&self) -> u8 {
        self.phase.phase()
    }

    pub(crate) fn resource_transfer(&self) -> Option<&crate::controller_resource_reservation::Q04ResourceTransferV1> {
        self.resource
    }

    pub(crate) fn same_original_cut(&self, other: &Self) -> bool {
        self.identity == other.identity && std::ptr::eq(self.ledger, other.ledger)
    }

    pub(crate) fn require_signing_binding(&self, proposed: &[u8]) -> Result<(), CreateQ04ErrorV1> {
        if crate::policy_compiler::closed_policy_binding_digest_v2(proposed)? != self.identity.binding() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    pub(crate) fn require_fixed_owner(&self, journal: &Journal) -> Result<(), CreateQ04ErrorV1> {
        crate::policy_compiler::validate_current_create_controller_journal_v1(journal)?;
        if journal.protected_owner_uid()? != self.identity.controller_uid() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    pub(crate) fn require_current_readback(&self, journal: &Journal) -> Result<(), CreateQ04ErrorV1> {
        self.require_fixed_owner(journal)?;
        let current = current_readback(journal.native.state())?;
        let history = current.q04.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if history.identity != *self.identity
            || history.phases.len() != usize::from(self.phase.phase())
            || history.phases.last() != Some(self.phase)
            || current.hold.map(ControllerPolicyHoldV1::source)
                != Some(self.ledger.source_commitment())
            || !crate::reconciler::require_q04_original_pending_v1(journal)?
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }
}

// Derive the actual held prefix from the sole canonical history engine, not
// from a nominated phase/sequence. The full native observer separately joins
// these exact recipe bytes to the same original Journal's committed history.
#[cfg(target_os = "linux")]
pub(super) fn require_q04_signing_prefix(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transitions: &[ControllerQ04TransitionV1<'_>],
) -> Result<usize, CreateQ04ErrorV1> {
    require_q04_owner_prefix(state, transitions, Q04ControllerPrefixPurposeV1::HeldSigner)
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_refresh_prefix(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transitions: &[ControllerQ04TransitionV1<'_>],
) -> Result<usize, CreateQ04ErrorV1> {
    require_q04_owner_prefix(state, transitions, Q04ControllerPrefixPurposeV1::Gen1Refresh)
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Q04ControllerPrefixPurposeV1 {
    HeldSigner,
    Gen1Refresh,
}

// These two private purposes share exact canonical history/recipe matching.
// Gen1 refresh may observe a released prefix but cannot mint a held packet,
// waive a commit gate or change any phase. The signer remains restricted1..4.
#[cfg(target_os = "linux")]
fn require_q04_owner_prefix(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transitions: &[ControllerQ04TransitionV1<'_>],
    purpose: Q04ControllerPrefixPurposeV1,
) -> Result<usize, CreateQ04ErrorV1> {
    if transitions.len() != 8 {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let readback = current_readback(state)?;
    let held = readback.hold.filter(|hold| {
        matches!(purpose, Q04ControllerPrefixPurposeV1::Gen1Refresh) || hold.is_held()
    })
        .ok_or(CreateQ04ErrorV1::ChangedCut)?;
    let history = readback.q04.ok_or(CreateQ04ErrorV1::ChangedCut)?;
    let prefix = history.phases.len();
    let last = match purpose {
        Q04ControllerPrefixPurposeV1::HeldSigner => 4,
        Q04ControllerPrefixPurposeV1::Gen1Refresh => 8,
    };
    if !(1..=last).contains(&prefix)
        || history.identity != *transitions[0].identity
        || held.source() != transitions[0].ledger.source_commitment()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    for (index, transition) in transitions.iter().enumerate() {
        if !transition.same_original_cut(&transitions[0])
            || transition.phase_number() != u8::try_from(index + 1)
                .map_err(|_| CreateQ04ErrorV1::Bounds)?
            || (index < prefix && history.phases.get(index) != Some(transition.phase))
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
    }
    Ok(prefix)
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_signing_original(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), CreateQ04ErrorV1> {
    let readback = current_readback(state)?;
    if readback.q04.is_some() || readback.hold.is_some_and(|hold| hold.is_held()) {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(super) fn require_q04_transition(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: &ControllerQ04TransitionV1<'_>,
) -> Result<(), JournalError> {
    if transaction != transition.transaction() {
        return Err(JournalError::ProtectedBoundary);
    }
    if let Some(resource) = transition.resource {
        resource.require_current(state, transaction)
            .map_err(|_| JournalError::ProtectedBoundary)?;
    }
    let prior_gate = transition.ledger.require_materialized_rows(state)
        .map_err(|cause| JournalError::Q04ControllerLedger(Box::new(cause)))?;
    let readback = current_readback(state)?;
    let number = transition.phase.phase();
    if number == 1 {
        if readback.hold.is_some() || readback.q04.is_some() || prior_gate.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
        return Ok(());
    }
    let history = readback.q04.ok_or(JournalError::ProtectedBoundary)?;
    let prior = history.phases.last().ok_or(JournalError::ProtectedBoundary)?;
    if history.identity != *transition.identity
        || history.phases.len() + 1 != usize::from(number)
        || readback.hold.map(ControllerPolicyHoldV1::source)
            != Some(transition.ledger.source_commitment())
    {
        return Err(JournalError::ProtectedBoundary);
    }
    transition.phase.require_successor(prior)?;
    if matches!(number, 4 | 7)
        && transition.phase.acknowledgement() != prior.acknowledgement()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    if prior.phase() == 1 {
        if prior_gate.is_some() {
            return Err(JournalError::ProtectedBoundary);
        }
    } else {
        let prior_gate = prior_gate.ok_or(JournalError::ProtectedBoundary)?;
        prior_gate.require_identity(
            transition.identity, transition.decision.ok_or(JournalError::ProtectedBoundary)?,
        )?;
        if prior_gate.status() != match prior.phase() { 2..=4 => 1, 5..=6 => 2, 7 => 3, 8 => 4, _ => 0 }
            || prior_gate.historical_consumed_record()?.digest().as_bytes() != &prior.bytes()[128..160]
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let acknowledgement_phase = match prior_gate.status() {
            1 => None,
            2 => Some(5),
            3 => Some(6),
            4 => Some(8),
            _ => return Err(JournalError::ProtectedBoundary),
        };
        if let Some(number) = acknowledgement_phase {
            let phase = history.phases.get(number - 1).ok_or(JournalError::ProtectedBoundary)?;
            if prior_gate.acknowledgement() != phase.acknowledgement() {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        if let Some(gate) = transition.gate {
            gate.require_successor(&prior_gate)?;
        }
    }
    Ok(())
}

pub(crate) fn v8_root_receipt_matches_ack(
    receipt: RootV8EffectAckV1,
    ack: ControllerPolicyV8EffectAckV1,
) -> Result<bool, JournalError> {
    canonical::v8_root_receipt_matches_ack(receipt, ack).map_err(JournalError::from)
}

fn encode_v8_root_receipt(
    receipt: RootV8EffectAckV1,
) -> Result<[u8; V8_ROOT_RECEIPT_RECORD_BYTES], JournalError> {
    canonical::encode_v8_root_receipt(receipt).map_err(JournalError::from)
}

/// Returns the digest of Controller's canonical retained Root ACK receipt.
///
/// # Errors
///
/// Rejects a Root ACK that cannot be encoded as an exact Controller receipt.
pub(crate) fn controller_v8_root_receipt_record_digest_v1(
    receipt: RootV8EffectAckV1,
) -> Result<ObjectDigest, JournalError> {
    canonical::controller_v8_root_receipt_record_digest_v1(receipt).map_err(JournalError::from)
}



fn decode_v8_root_receipt(bytes: &[u8]) -> Result<RootV8EffectAckV1, JournalError> {
    canonical::decode_v8_root_receipt(bytes).map_err(JournalError::from)
}

fn current_v8_attempt(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8AttemptV1>, JournalError> {
    canonical::current_v8_attempt(state).map_err(JournalError::from)
}

fn current_v8_ack(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8EffectAckV1>, JournalError> {
    canonical::current_v8_ack(state).map_err(JournalError::from)
}

fn current_v8_root_receipt(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<RootV8EffectAckV1>, JournalError> {
    canonical::current_v8_root_receipt(state).map_err(JournalError::from)
}

fn current_v8_floor(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8PreReleaseFloorV1>, JournalError> {
    canonical::current_v8_floor(state).map_err(JournalError::from)
}

fn current_v8_settlement(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<Option<ControllerPolicyV8SettlementV1>, JournalError> {
    canonical::current_v8_settlement(state).map_err(JournalError::from)
}

pub(super) fn require_no_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    canonical::require_no_mutation(state, transaction).map_err(JournalError::from)
}

pub(super) fn require_no_compaction(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    canonical::require_no_compaction(state).map_err(JournalError::from)
}

fn single_record_transaction(
    domain: &[u8],
    key: &[u8],
    bytes: &[u8],
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize();
    let id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            key.to_vec(),
            bytes.to_vec(),
        )],
    ).map_err(JournalError::from)
}

fn transaction(hold: ControllerPolicyHoldV1) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(TRANSACTION_DOMAIN, KEY, &hold.encode()?)
}

fn v8_attempt_transaction(
    attempt: ControllerPolicyV8AttemptV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(
        V8_ATTEMPT_TRANSACTION_DOMAIN,
        V8_ATTEMPT_KEY,
        &attempt.encode()?,
    )
}

fn v8_ack_transaction(
    ack: ControllerPolicyV8EffectAckV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(V8_ACK_TRANSACTION_DOMAIN, V8_ACK_KEY, &ack.encode()?)
}

fn v8_root_receipt_transaction(
    receipt: RootV8EffectAckV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(
        V8_ROOT_RECEIPT_TRANSACTION_DOMAIN,
        V8_ROOT_RECEIPT_KEY,
        &encode_v8_root_receipt(receipt)?,
    )
}

fn v8_root_receipt_capacity_transaction(
    hold: ControllerPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    // Preflight only: the real receipt has this exact key and encoded length.
    // No synthetic Root row is committed or exposed as authority.
    let digest = Sha256::new()
        .chain_update(V8_ROOT_RECEIPT_TRANSACTION_DOMAIN)
        .chain_update(b"capacity-preflight\0")
        .chain_update(hold.encode()?)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
            vec![0; V8_ROOT_RECEIPT_RECORD_BYTES],
        )],
    ).map_err(JournalError::from)
}

fn v8_floor_transaction(
    floor: ControllerPolicyV8PreReleaseFloorV1,
) -> Result<JournalTransaction, JournalError> {
    single_record_transaction(V8_FLOOR_TRANSACTION_DOMAIN, V8_FLOOR_KEY, &floor.encode()?)
}

fn v8_floor_capacity_transaction(
    hold: ControllerPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    let digest = Sha256::new()
        .chain_update(V8_FLOOR_TRANSACTION_DOMAIN)
        .chain_update(b"capacity-preflight\0")
        .chain_update(hold.encode()?)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerPolicyHold,
            V8_FLOOR_KEY.to_vec(),
            vec![0; V8_FLOOR_RECORD_BYTES],
        )],
    ).map_err(JournalError::from)
}

fn v8_settlement_transaction(
    released: ControllerPolicyHoldV1,
    settlement: ControllerPolicyV8SettlementV1,
) -> Result<JournalTransaction, JournalError> {
    let hold_bytes = released.encode()?;
    let settlement_bytes = settlement.encode()?;
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_TRANSACTION_DOMAIN)
        .chain_update(hold_bytes)
        .chain_update(settlement_bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                KEY.to_vec(),
                hold_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                V8_SETTLEMENT_KEY.to_vec(),
                settlement_bytes.to_vec(),
            ),
        ],
    ).map_err(JournalError::from)
}

fn v8_settlement_capacity_transaction(
    held: ControllerPolicyHoldV1,
) -> Result<JournalTransaction, JournalError> {
    let released = ControllerPolicyHoldV1 {
        held: false,
        ..held
    };
    let hold_bytes = released.encode()?;
    let digest = Sha256::new()
        .chain_update(V8_SETTLEMENT_TRANSACTION_DOMAIN)
        .chain_update(b"capacity-preflight\0")
        .chain_update(hold_bytes)
        .finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| JournalError::ProtectedBoundary)?;
    JournalTransaction::new(
        id,
        vec![
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                KEY.to_vec(),
                hold_bytes.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::ControllerPolicyHold,
                V8_SETTLEMENT_KEY.to_vec(),
                vec![0; V8_SETTLEMENT_RECORD_BYTES],
            ),
        ],
    ).map_err(JournalError::from)
}

fn ensure_controller(journal: &Journal) -> Result<(), JournalError> {
    journal.ensure_protected_authority()?;
    if journal.native.protected_view().map(|location| location.name()) != Some("controller.journal") {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

impl Journal {
    /// Durably freezes the protected Controller journal before root Q04 submission.
    ///
    /// A lost root reply leaves this hold intact across process death. The
    /// caller must not release it on successful terminal-ACK write alone.
    ///
    /// # Errors
    ///
    /// Rejects an unprotected journal, existing held or malformed custody,
    /// invalid fields, or a failed durable write/readback.
    pub fn acquire_controller_policy_hold_v1(
        &mut self,
        hold: ControllerPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        if !hold.is_held()
            || current(self.native.state())?.is_some_and(ControllerPolicyHoldV1::is_held)
            || current_v8_attempt(self.native.state())?.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let acquire = transaction(hold)?;
        let attempt = v8_attempt_transaction(ControllerPolicyV8AttemptV1::new(
            hold,
            ObjectDigest::from_bytes([1; 32]),
        )?)?;
        let v8_ack = v8_ack_transaction(ControllerPolicyV8EffectAckV1::new(
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([1; 32]))?,
            1,
            [1; 16],
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([1; 32]),
        )?)?;
        let v8_root_receipt = v8_root_receipt_capacity_transaction(hold)?;
        let v8_floor = v8_floor_capacity_transaction(hold)?;
        let v8_settlement = v8_settlement_capacity_transaction(hold)?;
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(&[
                acquire.clone(),
                attempt,
                v8_ack,
                v8_root_receipt,
                v8_floor,
                v8_settlement,
            ]),
            PreflightScope {
                allow_policy_hold_transition: true,
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        self.commit_in_scope(
            &acquire,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        if current(self.native.state())? != Some(hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads the exact Controller custody state under its protected writer.
    ///
    /// This observation does not attest the root owner's state.
    ///
    /// # Errors
    ///
    /// Rejects unprotected or malformed custody.
    pub fn controller_policy_hold_v1(
        &self,
    ) -> Result<Option<ControllerPolicyHoldV1>, JournalError> {
        ensure_controller(self)?;
        current(self.native.state())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn controller_q04_history_v1(
        &self,
    ) -> Result<Option<ControllerQ04HistoryV1>, JournalError> {
        ensure_controller(self)?;
        Ok(current_readback(self.native.state())?.q04)
    }

    /// Reads the exact protected V8 pre-send attempt under Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects unprotected, malformed, or mixed hold state.
    pub fn controller_policy_v8_attempt_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8AttemptV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_attempt(self.native.state())
    }

    /// Retains the exact V8 terminal digest before sending it to Root.
    ///
    /// An ambiguous append is recovered by reopening this same protected
    /// Controller journal. Identical replay is idempotent; a second terminal
    /// attempt is forbidden while the first remains unresolved.
    ///
    /// # Errors
    ///
    /// Rejects a stale hold, prior ACK or different attempt, unsafe journal,
    /// exhausted reserved capacity, or failed durable readback.
    pub fn record_controller_policy_v8_attempt_v1(
        &mut self,
        attempt: ControllerPolicyV8AttemptV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        attempt.validate()?;
        if current(self.native.state())? != Some(attempt.hold) {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_v8_attempt(self.native.state())? {
            Some(prior) if prior == attempt => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }
        self.commit_in_scope(
            &v8_attempt_transaction(attempt)?,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        if current_v8_attempt(self.native.state())? != Some(attempt) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads the exact historical V8 no-Apply effect acknowledgment.
    ///
    /// This protected local replay does not reauthenticate Root or Cache and
    /// cannot be used as a release or effect capability on its own.
    ///
    /// # Errors
    ///
    /// Rejects unprotected, malformed, or mixed Controller custody.
    pub fn controller_policy_v8_effect_ack_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8EffectAckV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_ack(self.native.state())
    }

    /// Durably advances one exact V8 attempt to a no-Apply effect ACK.
    ///
    /// The caller must first join Root's authenticated AOSPCP02 replay to the
    /// still-held Controller, Source, and protected/physical Cache writer cut.
    /// An identical cold replay is idempotent; this does not permit release.
    ///
    /// # Errors
    ///
    /// Rejects a changed attempt, released hold, mixed V1 acknowledgment,
    /// conflicting replay, or failed protected commit/readback.
    pub fn acknowledge_controller_policy_v8_effect_v1(
        &mut self,
        ack: ControllerPolicyV8EffectAckV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        ack.validate()?;
        if current(self.native.state())? != Some(ack.attempt.hold)
            || current_v8_attempt(self.native.state())? != Some(ack.attempt)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_v8_ack(self.native.state())? {
            Some(prior) if prior == ack => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }
        self.commit_in_scope(
            &v8_ack_transaction(ack)?,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        if current_v8_ack(self.native.state())? != Some(ack) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Reads the exact historical Root V8 ACK retained under Controller custody.
    ///
    /// This receipt grants no release, public Create, or Apply authority.
    ///
    /// # Errors
    ///
    /// Rejects unprotected or inconsistent Controller custody.
    pub fn controller_policy_v8_root_receipt_v1(
        &self,
    ) -> Result<Option<RootV8EffectAckV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_root_receipt(self.native.state())
    }

    /// Retains one authenticated historical Root V8 ACK under the held writer.
    ///
    /// The caller must authenticate Root and join the exact Source and Cache
    /// cut first. Identical cold replay is idempotent; this grants no release.
    ///
    /// # Errors
    ///
    /// Rejects changed Create, attempt, ACK, or Root receipt, or a failed
    /// protected commit and readback.
    pub fn record_controller_policy_v8_root_receipt_v1(
        &mut self,
        receipt: RootV8EffectAckV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        let ack = current_v8_ack(self.native.state())?.ok_or(JournalError::ProtectedBoundary)?;
        if current(self.native.state())? != Some(ack.attempt().hold())
            || !v8_root_receipt_matches_ack(receipt, ack)?
        {
            return Err(JournalError::ProtectedBoundary);
        }
        match current_v8_root_receipt(self.native.state())? {
            Some(prior) if prior == receipt => return Ok(()),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }
        self.commit_in_scope(
            &v8_root_receipt_transaction(receipt)?,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        if current_v8_root_receipt(self.native.state())? != Some(receipt) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }

    /// Records the held Cache and Source cut after Root has durably released.
    ///
    /// A future caller must supply `root_release_marker` only from a peer-checked
    /// R8X Released proof while Controller, Source, and Cache writers remain
    /// held. This floor authorizes no owner release, successor, Create, or Apply.
    /// It persists through the later Controller S row for exact cold recovery.
    ///
    /// # Errors
    ///
    /// Rejects a changed V8 chain, held owner identity, Root marker, or prior
    /// floor, or a failed durable commit and typed readback.
    #[allow(dead_code)]
    pub(crate) fn record_controller_policy_v8_pre_release_floor_v1(
        &mut self,
        expected: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
        root_release_marker: ObjectDigest,
        cache_held: CachePolicyHoldV1,
        source_held: SourceDomainPolicyHoldV1,
    ) -> Result<ControllerPolicyV8PreReleaseFloorV1, JournalError> {
        ensure_controller(self)?;
        let attempt = current_v8_attempt(self.native.state())?.ok_or(JournalError::ProtectedBoundary)?;
        let ack = current_v8_ack(self.native.state())?.ok_or(JournalError::ProtectedBoundary)?;
        if current(self.native.state())? != Some(expected)
            || !expected.is_held()
            || attempt.hold() != expected
            || ack.attempt() != attempt
            || !v8_root_receipt_matches_ack(receipt, ack)?
            || current_v8_root_receipt(self.native.state())? != Some(receipt)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let floor = ControllerPolicyV8PreReleaseFloorV1::from_held_rows(
            expected,
            receipt,
            root_release_marker,
            cache_held,
            source_held,
        )?;
        match current_v8_floor(self.native.state())? {
            Some(prior) if prior == floor => return Ok(floor),
            Some(_) => return Err(JournalError::ProtectedBoundary),
            None => {}
        }

        self.commit_in_scope(
            &v8_floor_transaction(floor)?,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        if current(self.native.state())? != Some(expected) || current_v8_floor(self.native.state())? != Some(floor)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(floor)
    }

    /// Reads the exact pre-release floor under the protected Controller writer.
    ///
    /// # Errors
    ///
    /// Rejects foreign or malformed Controller custody.
    #[allow(dead_code)]
    pub(crate) fn controller_policy_v8_pre_release_floor_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8PreReleaseFloorV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_floor(self.native.state())
    }

    /// Atomically retires Controller V8 custody with exact owner-release evidence.
    ///
    /// The caller must obtain the Root marker digest from a peer-checked R8X
    /// Released proof and Cache/Source rows from their retained writers. This
    /// inert local primitive does not authenticate those owners itself or grant
    /// Root successor, public Create, or Apply. The retained V8 attempt keeps
    /// ordinary Controller mutations fenced after local release.
    ///
    /// # Errors
    ///
    /// Rejects an incomplete or changed V8 chain, owner evidence, Controller
    /// hold, or failed atomic commit and typed readback. Exact cold replay is
    /// idempotent; a different release proof fails closed.
    #[allow(dead_code)]
    pub(crate) fn retire_controller_policy_v8_hold_with_settlement_v1(
        &mut self,
        expected: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
        evidence: ControllerPolicyV8ReleaseEvidenceV1,
    ) -> Result<ControllerPolicyV8SettlementV1, JournalError> {
        ensure_controller(self)?;
        evidence.validate_for(expected)?;
        if !expected.is_held() {
            return Err(JournalError::ProtectedBoundary);
        }
        current(self.native.state())?;
        let attempt = current_v8_attempt(self.native.state())?.ok_or(JournalError::ProtectedBoundary)?;
        let ack = current_v8_ack(self.native.state())?.ok_or(JournalError::ProtectedBoundary)?;
        if attempt.hold() != expected
            || ack.attempt() != attempt
            || !v8_root_receipt_matches_ack(receipt, ack)?
            || current_v8_root_receipt(self.native.state())? != Some(receipt)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let floor = current_v8_floor(self.native.state())?.ok_or(JournalError::ProtectedBoundary)?;
        if floor.root_release_marker != evidence.root_release_marker
            || floor.cache_held != evidence.cache_held.record_digest()?
            || floor.source_held != evidence.source_held.record_digest()?
        {
            return Err(JournalError::ProtectedBoundary);
        }

        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        let settlement = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt,
            ack,
            receipt,
            evidence.root_release_marker,
            evidence.cache_released.record_digest()?,
            evidence.source_released.record_digest()?,
        )?;
        match current(self.native.state())? {
            Some(prior) if prior == released => {
                if current_v8_settlement(self.native.state())? == Some(settlement) {
                    return Ok(settlement);
                }
                return Err(JournalError::ProtectedBoundary);
            }
            Some(prior) if prior == expected && current_v8_settlement(self.native.state())?.is_none() => {}
            _ => return Err(JournalError::ProtectedBoundary),
        }

        self.commit_in_scope(
            &v8_settlement_transaction(released, settlement)?,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        if current(self.native.state())? != Some(released)
            || current_v8_root_receipt(self.native.state())? != Some(receipt)
            || current_v8_settlement(self.native.state())? != Some(settlement)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(settlement)
    }

    /// Reads the canonical local V8 settlement row under Controller custody.
    ///
    /// # Errors
    ///
    /// Rejects a foreign or malformed protected Controller journal.
    #[allow(dead_code)]
    pub(crate) fn controller_policy_v8_settlement_v1(
        &self,
    ) -> Result<Option<ControllerPolicyV8SettlementV1>, JournalError> {
        ensure_controller(self)?;
        current_v8_settlement(self.native.state())
    }

    pub(crate) fn release_controller_policy_hold_after_root_readback_v1(
        &mut self,
        expected: ControllerPolicyHoldV1,
    ) -> Result<(), JournalError> {
        ensure_controller(self)?;
        // An inert hold can release only before a V8 attempt is retained.
        if !expected.held
            || current(self.native.state())? != Some(expected)
            || current_v8_attempt(self.native.state())?.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        let transaction = transaction(released)?;
        self.commit_in_scope(
            &transaction,
            AppendScope {
                allow_policy_hold_transition: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        if current(self.native.state())? != Some(released) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;

    use super::*;
    use crate::journal::{JournalLimits, RecordMutationRef};
    use aos_sandbox_core::ProjectId;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aos-controller-policy-hold-{}-{}",
                std::process::id(),
                OperationId::new()
            ));
            fs::create_dir(&path).expect("test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("protected directory mode");
            Self(path)
        }

        fn open(&self) -> Journal {
            let uid = fs::metadata(&self.0).expect("directory metadata").uid();
            Journal::open_protected_at_uid(
                &self.0,
                "controller.journal",
                JournalLimits::default(),
                uid,
            )
            .expect("protected Controller reopen")
            .0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn hold() -> ControllerPolicyHoldV1 {
        ControllerPolicyHoldV1::new(
            OperationId::from_bytes([1; 16]),
            SandboxId::from_bytes([2; 16]),
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([4; 32]),
            7,
        )
        .expect("valid hold")
    }

    fn ordinary_transaction() -> JournalTransaction {
        JournalTransaction::new(
            [9; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                b"ordinary".to_vec(),
                b"value".to_vec(),
            )],
        )
        .expect("ordinary transaction")
    }

    // Canonical retired DATA for the fixed hold fixture, with its original checksum.
    const RETIRED_ACK_BYTES: [u8; 208] = [
        65, 79, 83, 67, 84, 65, 48, 49, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0,
        0, 7, 0, 0, 0, 0, 0, 0, 0, 11, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
        12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
        13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 200, 65, 188, 5, 93, 34, 236, 212, 4, 184, 118, 45,
        176, 78, 33, 90, 142, 160, 181, 129, 180, 203, 222, 244, 50, 200, 77, 84, 75, 91, 187, 145,
    ];

    fn v8_root_receipt(ack: ControllerPolicyV8EffectAckV1) -> RootV8EffectAckV1 {
        let hold = ack.attempt().hold();
        let mut bytes = [0; ROOT_V8_EFFECT_ACK_RECORD_BYTES_V1];
        bytes[..8].copy_from_slice(b"AOSPC88A");
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..48].copy_from_slice(hold.binding().as_bytes());
        bytes[48..56].copy_from_slice(&hold.epoch().to_be_bytes());
        bytes[56..72].copy_from_slice(hold.operation().as_bytes());
        bytes[72..88].copy_from_slice(hold.sandbox().as_bytes());
        bytes[88..96].copy_from_slice(&ack.accepted_generation().to_be_bytes());
        bytes[96..112].copy_from_slice(&ack.effect_transaction());
        bytes[112..144].copy_from_slice(ack.attempt().terminal().as_bytes());
        bytes[144..176].copy_from_slice(ack.root_proof().as_bytes());
        bytes[176..208].copy_from_slice(ack.cache_quota().as_bytes());
        bytes[208..240].copy_from_slice(ack.record_digest().unwrap().as_bytes());
        bytes[240..272].fill(21);
        bytes[272..280].copy_from_slice(&4_u64.to_be_bytes());
        bytes[280..284].copy_from_slice(&1234_u32.to_be_bytes());
        bytes[284..300].fill(22);
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-effect-ack.v1\0")
            .chain_update(&bytes[..300])
            .finalize();
        bytes[300..].copy_from_slice(&checksum);
        RootV8EffectAckV1::from_record_bytes(&bytes).unwrap()
    }

    fn v8_release_evidence(
        controller: ControllerPolicyHoldV1,
    ) -> ControllerPolicyV8ReleaseEvidenceV1 {
        let cache_directory = tempfile::tempdir().unwrap();
        fs::set_permissions(cache_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cache_uid = fs::metadata(cache_directory.path()).unwrap().uid();
        Journal::initialize_cache_policy_hold_at(cache_directory.path(), cache_uid).unwrap();
        let cache_held = CachePolicyHoldV1::new(
            ProjectId::from_bytes([41; 16]),
            ObjectDigest::from_bytes([42; 32]),
            ObjectDigest::from_bytes([43; 32]),
            controller.binding(),
            controller.epoch(),
        )
        .unwrap();
        Journal::acquire_cache_policy_hold_at(cache_directory.path(), cache_uid, cache_held)
            .unwrap();
        let (mut cache_writer, _) = Journal::open_protected_at_uid(
            cache_directory.path(),
            crate::journal::CACHE_POLICY_HOLD_JOURNAL,
            Journal::cache_policy_hold_limits(),
            cache_uid,
        )
        .unwrap();
        cache_writer
            .release_v8_held_cache_policy_hold_for_writer(cache_held)
            .unwrap();
        let (cache_held, cache_released) = cache_writer
            .v8_pending_cache_policy_release_for_writer()
            .unwrap();

        let source_directory = tempfile::tempdir().unwrap();
        fs::set_permissions(source_directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let source_uid = fs::metadata(source_directory.path()).unwrap().uid();
        let (mut source, _) = Journal::open_protected_at_uid(
            source_directory.path(),
            "source-domains-v1.journal",
            JournalLimits::default(),
            source_uid,
        )
        .unwrap();
        let source_held = SourceDomainPolicyHoldV1::new(
            controller.operation(),
            controller.sandbox(),
            controller.source(),
            ObjectDigest::from_bytes([44; 32]),
            controller.binding(),
            controller.epoch(),
        )
        .unwrap();
        source
            .acquire_source_domain_policy_hold_v1(source_held)
            .unwrap();
        let source_held = source.source_domain_policy_hold_v1().unwrap().unwrap();
        source
            .retire_source_domain_policy_hold_v8(source_held)
            .unwrap();
        let (source_held, source_released) =
            source.source_domain_policy_v8_release_pair_v1().unwrap();

        ControllerPolicyV8ReleaseEvidenceV1::new(
            controller,
            ObjectDigest::from_bytes([45; 32]),
            cache_held,
            cache_released,
            source_held,
            source_released,
        )
        .unwrap()
    }

    fn record_v8_floor(
        controller: &mut Journal,
        hold: ControllerPolicyHoldV1,
        receipt: RootV8EffectAckV1,
        evidence: ControllerPolicyV8ReleaseEvidenceV1,
    ) -> ControllerPolicyV8PreReleaseFloorV1 {
        controller
            .record_controller_policy_v8_pre_release_floor_v1(
                hold,
                receipt,
                evidence.root_release_marker,
                evidence.cache_held,
                evidence.source_held,
            )
            .unwrap()
    }

    #[test]
    fn retired_ack_rows_refuse_without_mutating_live_or_reopened_journal() {
        use std::io::Write as _;

        for (released, mixed, malformed, empty) in [
            (false, false, false, false),
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let directory = TestDirectory::new();
            let expected = hold();
            let mut controller = directory.open();
            controller
                .acquire_controller_policy_hold_v1(expected)
                .unwrap();

            if mixed {
                let attempt =
                    ControllerPolicyV8AttemptV1::new(expected, ObjectDigest::from_bytes([28; 32]))
                        .unwrap();
                controller
                    .record_controller_policy_v8_attempt_v1(attempt)
                    .unwrap();
            } else if released {
                controller
                    .release_controller_policy_hold_after_root_readback_v1(expected)
                    .unwrap();
            }

            assert_eq!(
                controller
                    .controller_policy_hold_v1()
                    .unwrap()
                    .unwrap()
                    .is_held(),
                !released
            );
            let first_sequence = controller.snapshot_sequence();
            drop(controller);

            let bytes = if empty {
                Vec::new()
            } else if malformed {
                vec![1]
            } else {
                RETIRED_ACK_BYTES.to_vec()
            };
            let record = JournalTransaction::new(
                [71; 16],
                vec![JournalRecord::put(
                    RecordNamespace::ControllerPolicyHold,
                    ACK_KEY.to_vec(),
                    bytes.clone(),
                )],
            )
            .unwrap();
            let frames = aos_sandbox_protocol::domain_ledger::transaction::encode_transaction(
                &record,
                first_sequence,
            )
            .unwrap();
            let path = directory.0.join("controller.journal");
            let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
            for frame in &frames {
                file.write_all(frame).unwrap();
            }
            file.sync_all().unwrap();
            drop(file);
            let retained = fs::read(&path).unwrap();

            for _ in 0..2 {
                let mut reopened = directory.open();
                let sequence = reopened.snapshot_sequence();
                assert_eq!(
                    sequence,
                    first_sequence + u64::try_from(frames.len()).unwrap()
                );
                assert!(
                    reopened
                        .records(RecordNamespace::ControllerPolicyHold)
                        .any(|(key, value)| key == ACK_KEY && value == bytes.as_slice())
                );
                assert!(matches!(
                    reopened.controller_policy_hold_v1(),
                    Err(JournalError::ProtectedBoundary)
                ));
                assert!(matches!(
                    reopened.commit(&ordinary_transaction()),
                    Err(JournalError::ProtectedBoundary)
                ));
                assert!(matches!(
                    reopened.preflight_transactions(&[ordinary_transaction()]),
                    Err(JournalError::ProtectedBoundary)
                ));
                assert!(matches!(
                    reopened.compact(),
                    Err(JournalError::ProtectedBoundary)
                ));
                assert_eq!(reopened.snapshot_sequence(), sequence);
                drop(reopened);
                assert_eq!(fs::read(&path).unwrap(), retained);
            }
        }
    }

    #[test]
    fn released_hold_with_ack_is_not_valid_cold_state() {
        let expected = hold();
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        let mut state = BTreeMap::new();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            released.encode().unwrap().to_vec(),
        );
        state.insert(
            (RecordNamespace::ControllerPolicyHold, ACK_KEY.to_vec()),
            RETIRED_ACK_BYTES.to_vec(),
        );

        assert!(current(&state).is_err());
    }

    #[test]
    fn v8_terminal_attempt_is_durable_exact_and_fences_release() {
        let directory = TestDirectory::new();
        let expected = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(expected, ObjectDigest::from_bytes([28; 32]))
                .expect("canonical V8 attempt");
        let changed =
            ControllerPolicyV8AttemptV1::new(expected, ObjectDigest::from_bytes([29; 32]))
                .expect("different terminal");
        let mut controller = directory.open();
        assert!(
            controller
                .record_controller_policy_v8_attempt_v1(attempt)
                .is_err()
        );
        controller
            .acquire_controller_policy_hold_v1(expected)
            .unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            controller
                .record_controller_policy_v8_attempt_v1(changed)
                .is_err()
        );
        assert!(
            controller
                .release_controller_policy_hold_after_root_readback_v1(expected)
                .is_err()
        );
        assert!(controller.commit(&ordinary_transaction()).is_err());
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_v8_attempt_v1().unwrap(),
            Some(attempt)
        );
        reopened
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            reopened
                .record_controller_policy_v8_attempt_v1(changed)
                .is_err()
        );
        assert_eq!(reopened.records(RecordNamespace::Effect).count(), 0);

        let mut encoded = attempt.encode().unwrap();
        encoded[120] ^= 1;
        assert!(ControllerPolicyV8AttemptV1::decode(&encoded).is_err());
        let mut state = BTreeMap::new();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            ControllerPolicyHoldV1 {
                held: false,
                ..expected
            }
            .encode()
            .unwrap()
            .to_vec(),
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            attempt.encode().unwrap().to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "released hold cannot replay with attempt"
        );
    }

    #[test]
    fn v8_effect_ack_replays_exact_attempt_and_cannot_release() {
        let directory = TestDirectory::new();
        let hold = hold();
        let attempt = ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32]))
            .expect("V8 attempt");
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .expect("V8 no-Apply ACK");
        assert!(
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ObjectDigest::from_bytes([0; 32]),
                ack.cache_quota(),
            )
            .is_err()
        );
        assert!(
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ack.root_proof(),
                ObjectDigest::from_bytes([0; 32]),
            )
            .is_err()
        );
        let mut controller = directory.open();
        assert!(
            controller
                .acknowledge_controller_policy_v8_effect_v1(ack)
                .is_err()
        );
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        assert!(
            controller
                .acknowledge_controller_policy_v8_effect_v1(ack)
                .is_err()
        );
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        assert_eq!(
            controller.controller_policy_v8_effect_ack_v1().unwrap(),
            Some(ack)
        );
        assert_ne!(ack.record_digest().unwrap().as_bytes(), &[0; 32]);
        assert!(
            controller
                .release_controller_policy_hold_after_root_readback_v1(hold)
                .is_err()
        );
        assert!(controller.commit(&ordinary_transaction()).is_err());
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_v8_effect_ack_v1().unwrap(),
            Some(ack)
        );
        for changed in [
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                14,
                [14; 16],
                ack.root_proof(),
                ack.cache_quota(),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [17; 16],
                ack.root_proof(),
                ack.cache_quota(),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ObjectDigest::from_bytes([18; 32]),
                ack.cache_quota(),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                attempt,
                13,
                [14; 16],
                ack.root_proof(),
                ObjectDigest::from_bytes([19; 32]),
            )
            .unwrap(),
            ControllerPolicyV8EffectAckV1::new(
                ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([20; 32])).unwrap(),
                13,
                [14; 16],
                ack.root_proof(),
                ack.cache_quota(),
            )
            .unwrap(),
        ] {
            assert!(
                reopened
                    .acknowledge_controller_policy_v8_effect_v1(changed)
                    .is_err()
            );
        }
        reopened
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();

        let mut malformed = ack.encode().unwrap();
        malformed[224] ^= 1;
        assert!(ControllerPolicyV8EffectAckV1::decode(&malformed).is_err());
        let mut state = BTreeMap::new();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            hold.encode().unwrap().to_vec(),
        );
        state.insert(
            (RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()),
            ack.encode().unwrap().to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "ACK without attempt is not recoverable"
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            attempt.encode().unwrap().to_vec(),
        );
        assert_eq!(current_v8_ack(&state).unwrap(), Some(ack));
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([20; 32]))
                .unwrap()
                .encode()
                .unwrap()
                .to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "substituted attempt fails cold replay"
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_ATTEMPT_KEY.to_vec(),
            ),
            attempt.encode().unwrap().to_vec(),
        );
        state.insert(
            (RecordNamespace::ControllerPolicyHold, ACK_KEY.to_vec()),
            RETIRED_ACK_BYTES.to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "mixed V1 and V8 ACKs fail cold replay"
        );
        state.remove(&(RecordNamespace::ControllerPolicyHold, ACK_KEY.to_vec()));
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            ControllerPolicyHoldV1 {
                held: false,
                ..hold
            }
            .encode()
            .unwrap()
            .to_vec(),
        );
        assert!(
            current(&state).is_err(),
            "released hold plus ACK fails cold replay"
        );
    }

    #[test]
    fn v8_root_receipt_replays_exactly_and_keeps_controller_frozen() {
        let directory = TestDirectory::new();
        let hold = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32])).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .unwrap();
        let receipt = v8_root_receipt(ack);
        let mut controller = directory.open();
        assert!(
            controller
                .record_controller_policy_v8_root_receipt_v1(receipt)
                .is_err()
        );
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            controller
                .record_controller_policy_v8_root_receipt_v1(receipt)
                .is_err()
        );
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        controller
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        assert_eq!(
            controller.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
        reopened
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        let mut changed = receipt.record_bytes().unwrap();
        changed[240] ^= 1;
        let checksum = Sha256::new()
            .chain_update(b"aos.sandbox.policy-compiler.root-v8-effect-ack.v1\0")
            .chain_update(&changed[..300])
            .finalize();
        changed[300..].copy_from_slice(&checksum);
        let changed = RootV8EffectAckV1::from_record_bytes(&changed).unwrap();
        assert!(
            reopened
                .record_controller_policy_v8_root_receipt_v1(changed)
                .is_err()
        );
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(hold)
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
        assert_eq!(reopened.records(RecordNamespace::Effect).count(), 0);

        let mut encoded = encode_v8_root_receipt(receipt).unwrap();
        encoded[16] ^= 1;
        assert!(decode_v8_root_receipt(&encoded).is_err());
        let mut state = reopened.native.state().clone();
        state.remove(&(RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()));
        assert!(current(&state).is_err(), "receipt requires the exact ACK");

        let mut state = reopened.native.state().clone();
        let changed_ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            ack.accepted_generation() + 1,
            ack.effect_transaction(),
            ack.root_proof(),
            ack.cache_quota(),
        )
        .unwrap();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, V8_ACK_KEY.to_vec()),
            changed_ack.encode().unwrap().to_vec(),
        );
        assert!(current(&state).is_err(), "changed Create fails cold replay");

        let mut state = reopened.native.state().clone();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            ControllerPolicyHoldV1 {
                held: false,
                ..hold
            }
            .encode()
            .unwrap()
            .to_vec(),
        );
        assert!(current(&state).is_err(), "released V8 requires settlement");
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..hold
        };
        let evidence = v8_release_evidence(hold);
        let floor = ControllerPolicyV8PreReleaseFloorV1::from_held_rows(
            hold,
            receipt,
            evidence.root_release_marker,
            evidence.cache_held,
            evidence.source_held,
        )
        .unwrap();
        let settlement = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt,
            ack,
            receipt,
            evidence.root_release_marker,
            evidence.cache_released.record_digest().unwrap(),
            evidence.source_released.record_digest().unwrap(),
        )
        .unwrap();
        state.insert(
            (RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()),
            floor.encode().unwrap().to_vec(),
        );
        state.insert(
            (
                RecordNamespace::ControllerPolicyHold,
                V8_SETTLEMENT_KEY.to_vec(),
            ),
            settlement.encode().unwrap().to_vec(),
        );
        assert_eq!(
            current(&state).unwrap(),
            Some(released),
            "the complete V8 chain and settlement admit exact released replay"
        );
        state.remove(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
        ));
        assert!(current(&state).is_err(), "release requires Root receipt");
    }

    #[test]
    fn v8_settlement_requires_complete_chain_and_replays_exactly() {
        let directory = TestDirectory::new();
        let hold = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32])).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .unwrap();
        let receipt = v8_root_receipt(ack);
        let evidence = v8_release_evidence(hold);
        let mut controller = directory.open();

        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err()
        );
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err()
        );
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err()
        );
        controller
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .is_err(),
            "settlement requires a durable pre-release floor"
        );
        let floor = record_v8_floor(&mut controller, hold, receipt, evidence);
        assert_eq!(
            controller
                .controller_policy_v8_pre_release_floor_v1()
                .unwrap(),
            Some(floor)
        );
        assert_eq!(
            record_v8_floor(&mut controller, hold, receipt, evidence),
            floor,
            "exact pre-release floor replay is idempotent"
        );
        assert_eq!(
            floor.cache_held_digest(),
            evidence.cache_held.record_digest().unwrap()
        );
        assert_eq!(
            floor.source_held_digest(),
            evidence.source_held.record_digest().unwrap()
        );
        assert_eq!(
            floor.root_release_marker_digest(),
            evidence.root_release_marker
        );
        assert_ne!(floor.record_digest().unwrap().as_bytes(), &[0; 32]);
        assert_eq!(
            ControllerPolicyV8PreReleaseFloorV1::from_record_bytes(&floor.record_bytes().unwrap())
                .unwrap(),
            floor
        );

        let changed_cache = CachePolicyHoldV1::new(
            ProjectId::from_bytes([47; 16]),
            evidence.cache_held.partition(),
            evidence.cache_held.cache_head(),
            hold.binding(),
            hold.epoch(),
        )
        .unwrap();
        let changed_source = SourceDomainPolicyHoldV1::new(
            hold.operation(),
            hold.sandbox(),
            hold.source(),
            ObjectDigest::from_bytes([48; 32]),
            hold.binding(),
            hold.epoch(),
        )
        .unwrap();
        for (marker, cache, source) in [
            (
                ObjectDigest::from_bytes([46; 32]),
                evidence.cache_held,
                evidence.source_held,
            ),
            (
                evidence.root_release_marker,
                changed_cache,
                evidence.source_held,
            ),
            (
                evidence.root_release_marker,
                evidence.cache_held,
                changed_source,
            ),
        ] {
            assert!(
                controller
                    .record_controller_policy_v8_pre_release_floor_v1(
                        hold, receipt, marker, cache, source,
                    )
                    .is_err(),
                "changed held or Root evidence cannot replace the floor"
            );
        }
        drop(controller);

        let mut controller = directory.open();
        assert_eq!(
            controller
                .controller_policy_v8_pre_release_floor_v1()
                .unwrap(),
            Some(floor),
            "the exact floor survives cold replay while all writers remain held"
        );
        assert_eq!(
            record_v8_floor(&mut controller, hold, receipt, evidence),
            floor
        );

        let changed_hold = ControllerPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([29; 32]),
            ..hold
        };
        let changed_ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            14,
            ack.effect_transaction(),
            ack.root_proof(),
            ack.cache_quota(),
        )
        .unwrap();
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(
                    changed_hold,
                    receipt,
                    evidence,
                )
                .is_err()
        );
        assert!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(
                    hold,
                    v8_root_receipt(changed_ack),
                    evidence,
                )
                .is_err()
        );
        assert_eq!(controller.controller_policy_hold_v1().unwrap(), Some(hold));

        let settlement = controller
            .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
            .unwrap();
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..hold
        };
        assert_eq!(
            controller.controller_policy_hold_v1().unwrap(),
            Some(released)
        );
        assert_eq!(
            controller.controller_policy_v8_settlement_v1().unwrap(),
            Some(settlement)
        );
        assert!(controller.commit(&ordinary_transaction()).is_err());
        assert!(require_no_compaction(controller.native.state()).is_err());
        assert_eq!(controller.records(RecordNamespace::Effect).count(), 0);
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_hold_v1().unwrap(),
            Some(released)
        );
        assert_eq!(
            reopened.controller_policy_v8_attempt_v1().unwrap(),
            Some(attempt)
        );
        assert_eq!(
            reopened.controller_policy_v8_effect_ack_v1().unwrap(),
            Some(ack)
        );
        assert_eq!(
            reopened.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
        assert_eq!(
            reopened
                .controller_policy_v8_pre_release_floor_v1()
                .unwrap(),
            Some(floor)
        );
        assert_eq!(
            reopened.controller_policy_v8_settlement_v1().unwrap(),
            Some(settlement)
        );
        assert_eq!(
            ControllerPolicyV8SettlementV1::from_record_bytes(&settlement.record_bytes().unwrap())
                .unwrap(),
            settlement
        );
        assert_eq!(
            settlement.root_receipt_digest(),
            controller_v8_root_receipt_record_digest_v1(receipt).unwrap()
        );
        assert_eq!(
            reopened
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .unwrap(),
            settlement
        );
        assert_ne!(settlement.record_digest().unwrap().as_bytes(), &[0; 32]);

        let settled_state = reopened.native.state().clone();
        let mut torn = settled_state.clone();
        torn.remove(&(
            RecordNamespace::ControllerPolicyHold,
            V8_SETTLEMENT_KEY.to_vec(),
        ));
        assert!(current(&torn).is_err(), "release without S fails closed");
        let mut torn = settled_state.clone();
        torn.remove(&(RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()));
        assert!(current(&torn).is_err(), "S without floor fails closed");
        let mut torn = settled_state.clone();
        torn.remove(&(
            RecordNamespace::ControllerPolicyHold,
            V8_ROOT_RECEIPT_KEY.to_vec(),
        ));
        assert!(current(&torn).is_err(), "floor without R01 fails closed");
        let mut torn = settled_state.clone();
        torn.insert(
            (RecordNamespace::ControllerPolicyHold, KEY.to_vec()),
            hold.encode().unwrap().to_vec(),
        );
        assert!(current(&torn).is_err(), "S without release fails closed");

        for offset in [16, 48, 56, 88, 120, 152, 184, 216, 248] {
            let mut changed = settlement.encode().unwrap();
            changed[offset] ^= 1;
            let checksum = Sha256::new()
                .chain_update(V8_SETTLEMENT_CHECKSUM_DOMAIN)
                .chain_update(&changed[..280])
                .finalize();
            changed[280..].copy_from_slice(&checksum);
            reopened.native.apply_mutation(RecordMutationRef {
                namespace: RecordNamespace::ControllerPolicyHold,
                key: V8_SETTLEMENT_KEY,
                value: Some(&changed),
            });
            assert!(
                reopened
                    .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                    .is_err(),
                "changed settlement field at {offset} accepted"
            );
            reopened.native.apply_mutation(RecordMutationRef {
                namespace: RecordNamespace::ControllerPolicyHold,
                key: V8_SETTLEMENT_KEY,
                value: settled_state
                    .get(&(RecordNamespace::ControllerPolicyHold, V8_SETTLEMENT_KEY.to_vec()))
                    .map(Vec::as_slice),
            });
            assert_eq!(reopened.native.state(), &settled_state);
        }
        for offset in [16, 48, 56, 88, 120, 152] {
            let mut changed = floor.record_bytes().unwrap();
            changed[offset] ^= 1;
            let checksum = Sha256::new()
                .chain_update(v8_pre_release_floor::CHECKSUM_DOMAIN)
                .chain_update(&changed[..184])
                .finalize();
            changed[184..].copy_from_slice(&checksum);
            reopened.native.apply_mutation(RecordMutationRef {
                namespace: RecordNamespace::ControllerPolicyHold,
                key: V8_FLOOR_KEY,
                value: Some(&changed),
            });
            assert!(
                reopened
                    .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                    .is_err(),
                "changed floor field at {offset} accepted"
            );
            reopened.native.apply_mutation(RecordMutationRef {
                namespace: RecordNamespace::ControllerPolicyHold,
                key: V8_FLOOR_KEY,
                value: settled_state
                    .get(&(RecordNamespace::ControllerPolicyHold, V8_FLOOR_KEY.to_vec()))
                    .map(Vec::as_slice),
            });
            assert_eq!(reopened.native.state(), &settled_state);
        }
        let mut changed = floor.record_bytes().unwrap();
        changed[184] ^= 1;
        assert!(ControllerPolicyV8PreReleaseFloorV1::decode(&changed).is_err());
        let mut changed = settlement.encode().unwrap();
        changed[280] ^= 1;
        assert!(ControllerPolicyV8SettlementV1::decode(&changed).is_err());

        let changed_root = ControllerPolicyV8ReleaseEvidenceV1 {
            root_release_marker: ObjectDigest::from_bytes([46; 32]),
            ..evidence
        };
        assert!(
            reopened
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, changed_root,)
                .is_err()
        );
        assert!(reopened.acquire_controller_policy_hold_v1(hold).is_err());
        assert!(
            reopened
                .retire_controller_policy_v8_hold_with_settlement_v1(
                    changed_hold,
                    receipt,
                    evidence,
                )
                .is_err()
        );
        assert!(
            reopened
                .record_controller_policy_v8_root_receipt_v1(receipt)
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
    }

    #[test]
    fn v8_release_evidence_requires_matching_typed_owner_rows() {
        let controller = hold();
        let evidence = v8_release_evidence(controller);
        let wrong_cache = ControllerPolicyV8ReleaseEvidenceV1 {
            cache_held: CachePolicyHoldV1::new(
                ProjectId::from_bytes([47; 16]),
                evidence.cache_held.partition(),
                evidence.cache_held.cache_head(),
                controller.binding(),
                controller.epoch(),
            )
            .unwrap(),
            ..evidence
        };
        assert!(wrong_cache.validate_for(controller).is_err());

        let wrong_source = ControllerPolicyV8ReleaseEvidenceV1 {
            source_held: SourceDomainPolicyHoldV1::new(
                controller.operation(),
                controller.sandbox(),
                controller.source(),
                ObjectDigest::from_bytes([48; 32]),
                controller.binding(),
                controller.epoch(),
            )
            .unwrap(),
            ..evidence
        };
        assert!(wrong_source.validate_for(controller).is_err());

        for invalid in [
            ControllerPolicyV8ReleaseEvidenceV1 {
                root_release_marker: ObjectDigest::from_bytes([0; 32]),
                ..evidence
            },
            ControllerPolicyV8ReleaseEvidenceV1 {
                cache_released: evidence.cache_held,
                ..evidence
            },
            ControllerPolicyV8ReleaseEvidenceV1 {
                source_released: evidence.source_held,
                ..evidence
            },
        ] {
            assert!(invalid.validate_for(controller).is_err());
        }
    }

    #[test]
    fn lost_root_reply_freezes_controller_after_crash_and_reopen() {
        let directory = TestDirectory::new();
        let mut controller = directory.open();
        let expected = hold();
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..expected
        };
        assert!(
            controller
                .acquire_controller_policy_hold_v1(released)
                .is_err()
        );
        assert_eq!(controller.controller_policy_hold_v1().unwrap(), None);
        controller
            .acquire_controller_policy_hold_v1(expected)
            .expect("durable hold before root submit");
        drop(controller);

        let mut reopened = directory.open();
        assert_eq!(
            reopened.controller_policy_hold_v1().unwrap(),
            Some(expected)
        );
        assert!(matches!(
            reopened.commit(&ordinary_transaction()),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            reopened.preflight_transactions(&[ordinary_transaction()]),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(matches!(
            reopened.compact(),
            Err(JournalError::ProtectedBoundary)
        ));
        assert!(
            reopened
                .acquire_controller_policy_hold_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn exact_cold_release_restores_writes_but_wrong_binding_does_not() {
        let directory = TestDirectory::new();
        let mut controller = directory.open();
        let expected = hold();
        controller
            .acquire_controller_policy_hold_v1(expected)
            .unwrap();
        drop(controller);

        let mut reopened = directory.open();
        let wrong_binding = ControllerPolicyHoldV1 {
            binding: ObjectDigest::from_bytes([5; 32]),
            ..expected
        };
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(wrong_binding)
                .is_err()
        );
        assert!(reopened.commit(&ordinary_transaction()).is_err());
        reopened
            .release_controller_policy_hold_after_root_readback_v1(expected)
            .expect("exact root-released evidence is checked by caller");
        assert!(
            !reopened
                .controller_policy_hold_v1()
                .unwrap()
                .unwrap()
                .is_held()
        );
        reopened
            .commit(&ordinary_transaction())
            .expect("writes restored");
        assert!(
            reopened
                .release_controller_policy_hold_after_root_readback_v1(expected)
                .is_err()
        );
    }

    #[test]
    fn format_rejects_noncanonical_or_corrupt_custody() {
        let expected = hold();
        let mut bytes = expected.encode().unwrap();
        assert_eq!(ControllerPolicyHoldV1::decode(&bytes).unwrap(), expected);
        bytes[11] = 1;
        assert!(ControllerPolicyHoldV1::decode(&bytes).is_err());
        bytes = expected.encode().unwrap();
        bytes[119] ^= 1;
        assert!(ControllerPolicyHoldV1::decode(&bytes).is_err());
    }

    #[test]
    fn acquisition_reserves_capacity_for_v8_receipt_and_atomic_settlement() {
        for maximum_transactions in [1, 5] {
            let directory = TestDirectory::new();
            let uid = fs::metadata(&directory.0).unwrap().uid();
            let limits = JournalLimits {
                maximum_transactions,
                ..JournalLimits::default()
            };
            let (mut controller, _) =
                Journal::open_protected_at_uid(&directory.0, "controller.journal", limits, uid)
                    .expect("protected Controller");

            assert!(
                controller
                    .acquire_controller_policy_hold_v1(hold())
                    .is_err()
            );
            assert_eq!(controller.controller_policy_hold_v1().unwrap(), None);
        }

        let hold = hold();
        let attempt =
            ControllerPolicyV8AttemptV1::new(hold, ObjectDigest::from_bytes([28; 32])).unwrap();
        let ack = ControllerPolicyV8EffectAckV1::new(
            attempt,
            13,
            [14; 16],
            ObjectDigest::from_bytes([15; 32]),
            ObjectDigest::from_bytes([16; 32]),
        )
        .unwrap();
        let receipt = v8_root_receipt(ack);
        assert_eq!(
            crate::journal::encoded_transaction_record_bytes(
                &v8_root_receipt_capacity_transaction(hold).unwrap()
            )
            .unwrap(),
            crate::journal::encoded_transaction_record_bytes(
                &v8_root_receipt_transaction(receipt).unwrap()
            )
            .unwrap(),
        );
        let evidence = v8_release_evidence(hold);
        let floor = ControllerPolicyV8PreReleaseFloorV1::from_held_rows(
            hold,
            receipt,
            evidence.root_release_marker,
            evidence.cache_held,
            evidence.source_held,
        )
        .unwrap();
        assert_eq!(
            crate::journal::encoded_transaction_record_bytes(
                &v8_floor_capacity_transaction(hold).unwrap()
            )
            .unwrap(),
            crate::journal::encoded_transaction_record_bytes(&v8_floor_transaction(floor).unwrap())
                .unwrap(),
        );
        let released = ControllerPolicyHoldV1 {
            held: false,
            ..hold
        };
        let settlement = ControllerPolicyV8SettlementV1::from_chain(
            released,
            attempt,
            ack,
            receipt,
            evidence.root_release_marker,
            evidence.cache_released.record_digest().unwrap(),
            evidence.source_released.record_digest().unwrap(),
        )
        .unwrap();
        assert_eq!(
            crate::journal::encoded_transaction_record_bytes(
                &v8_settlement_capacity_transaction(hold).unwrap()
            )
            .unwrap(),
            crate::journal::encoded_transaction_record_bytes(
                &v8_settlement_transaction(released, settlement).unwrap()
            )
            .unwrap(),
        );

        let directory = TestDirectory::new();
        let uid = fs::metadata(&directory.0).unwrap().uid();
        let limits = JournalLimits {
            maximum_transactions: 6,
            ..JournalLimits::default()
        };
        let (mut controller, _) =
            Journal::open_protected_at_uid(&directory.0, "controller.journal", limits, uid)
                .expect("protected Controller");
        controller.acquire_controller_policy_hold_v1(hold).unwrap();
        controller
            .record_controller_policy_v8_attempt_v1(attempt)
            .unwrap();
        controller
            .acknowledge_controller_policy_v8_effect_v1(ack)
            .unwrap();
        controller
            .record_controller_policy_v8_root_receipt_v1(receipt)
            .unwrap();
        assert_eq!(
            record_v8_floor(&mut controller, hold, receipt, evidence),
            floor
        );
        assert_eq!(
            controller
                .retire_controller_policy_v8_hold_with_settlement_v1(hold, receipt, evidence)
                .unwrap(),
            settlement
        );
        assert_eq!(
            controller.controller_policy_v8_root_receipt_v1().unwrap(),
            Some(receipt)
        );
    }
}
