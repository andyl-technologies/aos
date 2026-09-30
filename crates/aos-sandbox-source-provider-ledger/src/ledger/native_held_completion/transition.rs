//! Closed Source checkpoints and exact canonical mutation proposals, without IO.

use std::collections::BTreeSet;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::native_held_completion::{
    NativeHeldControlKindV1 as Kind, NativeHeldSectionTagV1 as Tag,
    assertion::{NativeHeldDispositionV1, RootNativeObservationV1},
    frame::PreparedNativeHeldControlV1,
    recovery::{NativeHeldRecoveryModeV1 as Mode, ProviderNativeRecoveryStateV1},
};

use super::{
    SourceNativeHeldAdmissionBindingV1, SourceNativeHeldCompletionRecordV1 as Record, corrupt,
    evidence,
    graph::{self, Records},
    schema_error,
};
use crate::ledger::{
    LedgerFormatErrorV1, completion, format,
    model::{ProviderAcquisitionStateV1, ProviderAttemptStateV1},
    native_completion::{self, NativeAcquireCompletionStateV2 as Outer},
};

/// Names one fixed Source append in the native-only held contract.
///
/// These names describe DATA transitions, not authority to sign, dispatch,
/// replace a purpose-3 floor, or commit a protected journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceNativeHeldStepV1 {
    /// Adds Requested to a genuine dispatch-shaped Applying graph; no old native row.
    Requested,
    /// Records the independently durable original Issued challenge.
    ChallengeIssued,
    /// Adds the exact accepted reply and received Storage2 to Requested.
    StoragePrepared,
    /// Records the independently durable original Spent challenge.
    ChallengeSpent,
    /// Applies the existing authoritative six-row Complete reducers atomically.
    CompletionCommitted,
    /// Stores the reducer-bound unsigned Provider3 after Complete.
    HeldPrepared,
    /// Stores exactly that Provider3 signature archive and clears preparation.
    HeldStored,
    /// Records Root4/8 and the exact unsigned relay5 in the same append.
    RootDispositionPrepared,
    /// Stores exactly the retained relay5, before any send.
    RelayStored,
    /// Records the exact received Storage6 settlement.
    StorageSettlementRecorded,
    /// Stores the exact unsigned Provider7 stable settlement.
    ProviderSettledPrepared,
    /// Stores that Provider7 archive and clears preparation.
    ProviderSettledStored,
    /// Records the first exact mode-2 Root9, never an Observe query.
    RootRecoveryRecorded,
    /// Stores the exact unsigned11 for that original Root9.
    StorageRecoveryPrepared,
    /// Stores that first11 archive and clears preparation.
    StorageRecoveryQueryStored,
    /// Records exact received12; no new interest or acceptance is created.
    StorageRecoveryRecorded,
    /// Stores unsigned10 from the actual before row, possibly replacing unescaped7.
    ProviderRecoveryPrepared,
    /// Stores that first10 archive and clears preparation.
    ProviderRecoveryStored,
    /// Records exact received13 or current mode-3 Root9, never send success.
    RootTerminalRecorded,
}

/// Retains one exact canonical before/after value for capacity measurement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceNativeHeldMutationV1 {
    key: Vec<u8>,
    before: Option<Vec<u8>>,
    after: Vec<u8>,
}

impl SourceNativeHeldMutationV1 {
    /// Borrows the independently derived existing canonical family key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Borrows the actual canonical value before this append, or genuine initial absence.
    #[must_use]
    pub fn before(&self) -> Option<&[u8]> {
        self.before.as_deref()
    }

    /// Borrows the exact proposed canonical value, not a protected record token.
    #[must_use]
    pub fn after(&self) -> &[u8] {
        &self.after
    }
}

/// Retains a bounded validated DATA proposal for one Source-owned checkpoint.
///
/// A future original owner still must hold admission, current signatures,
/// clocks, challenge and capacity writers, validate the exact dispatch-domain
/// purpose-3 floor, and commit/read back before any escape. This value provides
/// neither a journal transaction nor permission to perform those effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceNativeHeldTransactionV1 {
    step: SourceNativeHeldStepV1,
    mutations: Vec<SourceNativeHeldMutationV1>,
    admission: Option<SourceNativeHeldAdmissionBindingV1>,
}

impl SourceNativeHeldTransactionV1 {
    /// Returns the closed checkpoint whose exact mutation shape was checked.
    #[must_use]
    pub const fn step(&self) -> SourceNativeHeldStepV1 {
        self.step
    }

    /// Borrows measured canonical mutations in sorted key order.
    #[must_use]
    pub fn mutations(&self) -> &[SourceNativeHeldMutationV1] {
        &self.mutations
    }

    /// Borrows original admission comparison fields only for the Requested append.
    ///
    /// The separate capacity reducer must join the actual old dispatch-domain
    /// purpose-3 record and atomically replace it with native9 plus these mutations.
    #[must_use]
    pub const fn admission(&self) -> Option<&SourceNativeHeldAdmissionBindingV1> {
        self.admission.as_ref()
    }
}

/// Checks complete actual graphs and proposes one closed native-held append.
///
/// Challenge checkpoints use the separately obtained canonical original row;
/// they never include that journal in Source's mutation list or claim atomicity
/// between journals. All own prepared controls bind the actual before bytes.
/// Signature provenance and live ownership remain independent obligations.
///
/// # Errors
///
/// Rejects an invalid graph, skipped/repeated checkpoint, rewritten archive,
/// wrong original dispatch lineage, unrelated mutation, fabricated cold phase,
/// stale before witness, or anything except the existing exact six-row Complete.
pub fn propose_native_held_transition_v1<'before, 'after>(
    before: impl IntoIterator<Item = (&'before [u8], &'before [u8])>,
    after: impl IntoIterator<Item = (&'after [u8], &'after [u8])>,
    acquisition: ObjectDigest,
    step: SourceNativeHeldStepV1,
    original_challenge: Option<&[u8]>,
) -> Result<SourceNativeHeldTransactionV1, LedgerFormatErrorV1> {
    let before = graph::collect(before)?;
    let after = graph::collect(after)?;
    graph::validate(&before)?;
    graph::validate(&after)?;
    crate::validate_transition_structure(&before, &after)?;
    let key = native_completion::native_completion_key_v2(acquisition);
    let next = Record::from_canonical_bytes(
        &key,
        after
            .get(&key)
            .ok_or(corrupt("held proposed native missing"))?,
    )?;
    let previous = before
        .get(&key)
        .map(|bytes| Record::from_canonical_bytes(&key, bytes))
        .transpose()?;
    validate_step(previous.as_ref(), &next, step)?;

    if step == SourceNativeHeldStepV1::Requested {
        validate_requested(&before, &next)?;
    } else {
        let previous = previous
            .as_ref()
            .ok_or(corrupt("held transition missing original"))?;
        if !permits_hot_checkpoint(previous.original.state, step) {
            return Err(corrupt(
                "held closed original custody cannot resume hot work",
            ));
        }
        validate_original(previous, &next, step)?;
    }
    match step {
        SourceNativeHeldStepV1::ChallengeIssued => {
            graph::validate_challenge(&next, original_challenge, false)?
        }
        SourceNativeHeldStepV1::ChallengeSpent | SourceNativeHeldStepV1::CompletionCommitted => {
            graph::validate_challenge(&next, original_challenge, true)?
        }
        _ => {}
    }
    if let Some(prepared) = next.suffix.prepared()
        && previous.as_ref().and_then(|value| value.suffix.prepared()) != Some(prepared)
    {
        graph::validate_prepared_witness(prepared, &before, &next, original_challenge)?;
        validate_recovery_before(prepared, &before, &next, previous.as_ref())?;
    }

    let keys = graph::companion_keys(&next)?;
    let pending_retirement = step == SourceNativeHeldStepV1::RootTerminalRecorded
        && matches!(next.original.state, Outer::Requested | Outer::Prepared);
    if pending_retirement {
        graph::validate_pending_retirement(
            &before,
            &after,
            previous.as_ref().ok_or(corrupt("held retirement before"))?,
            &next,
        )?;
    }
    let expected: BTreeSet<_> = checkpoint_owner_indices(step, next.original.state)
        .iter()
        .map(|index| keys[*index].clone())
        .collect();
    let mutations = exact_mutations(&before, &after, &expected)?;
    if step == SourceNativeHeldStepV1::CompletionCommitted {
        completion::validate_native_held_complete(&before, &after, &keys)?;
    }
    let admission = if step == SourceNativeHeldStepV1::Requested {
        Some(SourceNativeHeldAdmissionBindingV1::derive(&before, &next)?)
    } else {
        None
    };
    Ok(SourceNativeHeldTransactionV1 {
        step,
        mutations,
        admission,
    })
}

/// Shares mutation families without replacing exact graph/materializer checks.
pub(super) fn checkpoint_owner_indices(
    step: SourceNativeHeldStepV1,
    outer: Outer,
) -> &'static [usize] {
    if step == SourceNativeHeldStepV1::CompletionCommitted {
        &[0, 1, 2, 3, 4, 5]
    } else if step == SourceNativeHeldStepV1::RootTerminalRecorded
        && matches!(outer, Outer::Requested | Outer::Prepared)
    {
        &[1, 2, 3, 4, 5]
    } else {
        &[5]
    }
}

fn validate_requested(before: &Records, next: &Record) -> Result<(), LedgerFormatErrorV1> {
    let rows = graph::Companions::read(before, next)?;
    graph::validate_dispatch(
        &rows.acquisition,
        next.original.session_binding,
        next.original.attempt_digest,
    )?;
    if rows.acquisition.state != ProviderAcquisitionStateV1::Applying
        || rows.attempt.state != ProviderAttemptStateV1::Reserved
        || rows.holder.pending_attempt_digest != Some(next.original.attempt_digest)
        || next.original.reservation_acquisition_digest
            != Some(format::record_digest(
                before
                    .get(&rows.keys[2])
                    .ok_or(corrupt("held original Applying missing"))?,
            )?)
    {
        return Err(corrupt(
            "held Requested exact original Applying reservation",
        ));
    }
    Ok(())
}

pub(super) fn validate_original(
    before: &Record,
    after: &Record,
    step: SourceNativeHeldStepV1,
) -> Result<(), LedgerFormatErrorV1> {
    let revision = before
        .original
        .revision
        .checked_add(1)
        .ok_or(corrupt("held revision exhausted"))?;
    if after.original.revision != revision {
        return Err(corrupt("held checkpoint revision"));
    }
    let mut expected = after.original.clone();
    // The held suffix counts every append; legacy outer phases count only their
    // advances. Reuse its exact field predicate with a mechanical revision view.
    expected.revision = before.original.revision;
    if matches!(
        step,
        SourceNativeHeldStepV1::StoragePrepared | SourceNativeHeldStepV1::CompletionCommitted
    ) {
        expected.revision = revision;
    }
    before.original.validate_successor(&expected)
}

pub(crate) fn validate_step(
    before: Option<&Record>,
    after: &Record,
    step: SourceNativeHeldStepV1,
) -> Result<(), LedgerFormatErrorV1> {
    use SourceNativeHeldStepV1 as Step;
    if step == Step::Requested {
        if before.is_some()
            || after.original.revision != 1
            || after.original.state != Outer::Requested
            || after.suffix.phase() != 0
            || after.suffix.prepared().is_some()
            || after.suffix.controls().len() != 1
            || after.suffix.controls()[0].kind() != Kind::RootPrepared
        {
            return Err(corrupt("held initial Requested prefix"));
        }
        return Ok(());
    }
    let before = before.ok_or(corrupt("held original absent"))?;
    let phases = (before.suffix.phase(), after.suffix.phase());
    if !permits_checkpoint_phases(step, phases) || before.suffix.flight() != after.suffix.flight() {
        return Err(corrupt("held named checkpoint phases"));
    }
    if before.suffix.control(Kind::RootRecoveryQuery).is_some()
        && matches!(
            step,
            Step::RelayStored | Step::ProviderSettledPrepared | Step::ProviderSettledStored
        )
    {
        return Err(corrupt("held recovery cannot resume hot signing"));
    }
    let prior = before.suffix.controls();
    let next = after.suffix.controls();
    if !next.starts_with(prior) {
        return Err(corrupt("held append-once original archives"));
    }
    let added = &next[prior.len()..];
    match step {
        Step::ChallengeIssued | Step::ChallengeSpent | Step::CompletionCommitted => {
            if !added.is_empty() || before.suffix.prepared() != after.suffix.prepared() {
                return Err(corrupt("held checkpoint suffix rewrite"));
            }
        }
        Step::HeldPrepared
        | Step::ProviderSettledPrepared
        | Step::StorageRecoveryPrepared
        | Step::ProviderRecoveryPrepared => {
            let kind = preparation_kind(step).ok_or(corrupt("held preparation kind"))?;
            let replaces_preparation =
                permits_preparation_rotation(&CheckpointFacts::read(before)?, step, phases);
            if !added.is_empty()
                || after
                    .suffix
                    .prepared()
                    .is_none_or(|value| value.kind() != kind)
                || (before.suffix.prepared().is_some() && !replaces_preparation)
            {
                return Err(corrupt("held exact preparation checkpoint"));
            }
        }
        Step::RootDispositionPrepared => {
            require_added(added, |kind| {
                matches!(kind, Kind::RootAccepted | Kind::RootClosed)
            })?;
            if after
                .suffix
                .prepared()
                .is_none_or(|value| value.kind() != Kind::ProviderRelay)
                || (before.suffix.prepared().is_some()
                    && !(added[0].kind() == Kind::RootClosed
                        && before
                            .suffix
                            .prepared()
                            .is_some_and(|value| value.kind() == Kind::ProviderHeld)))
            {
                return Err(corrupt("held disposition plus unsigned relay"));
            }
        }
        Step::HeldStored
        | Step::RelayStored
        | Step::ProviderSettledStored
        | Step::StorageRecoveryQueryStored
        | Step::ProviderRecoveryStored => {
            let kind =
                stored_preparation_kind(step).ok_or(corrupt("held stored preparation kind"))?;
            require_added(added, |actual| actual == kind)?;
            if before.suffix.prepared() != Some(added[0].prepared())
                || after.suffix.prepared().is_some()
            {
                return Err(corrupt("held exact signed successor clears preparation"));
            }
        }
        Step::StoragePrepared
        | Step::RootRecoveryRecorded
        | Step::StorageSettlementRecorded
        | Step::StorageRecoveryRecorded
        | Step::RootTerminalRecorded => {
            require_added(added, |kind| match step {
                Step::StoragePrepared => kind == Kind::StorageHeld,
                Step::RootRecoveryRecorded => kind == Kind::RootRecoveryQuery,
                Step::StorageSettlementRecorded => kind == Kind::StorageSettled,
                Step::StorageRecoveryRecorded => kind == Kind::StorageRecoveryState,
                _ => matches!(kind, Kind::RootTerminalRecorded | Kind::RootRecoveryQuery),
            })?;
            let clears_unescaped_held = step == Step::RootRecoveryRecorded
                && permits_unescaped_held_clear(before, after, phases)?;
            if before.suffix.prepared() != after.suffix.prepared() && !clears_unescaped_held {
                return Err(corrupt("held received metadata rewrote preparation"));
            }
            if added[0].kind() == Kind::RootRecoveryQuery {
                let wanted = if step == Step::RootRecoveryRecorded {
                    Mode::SettleRecordedDisposition
                } else {
                    Mode::RecordRootTerminal
                };
                if evidence::query(added[0].prepared())?.mode != wanted {
                    return Err(corrupt("held exact recovery mode"));
                }
            }
        }
        Step::Requested => return Err(corrupt("held initial step reused")),
    }
    let before_facts = CheckpointFacts::read(before)?;
    let after_facts = CheckpointFacts::read(after)?;
    if !checkpoint_successors(before_facts)
        .iter()
        .any(|(candidate, facts)| *candidate == step && *facts == after_facts)
    {
        return Err(corrupt("held checkpoint artifact/predecessor shape"));
    }
    Ok(())
}

/// Projects bounded schema facts; it contains no synthetic signed control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CheckpointFacts {
    pub(super) phase: u8,
    pub(super) outer: Outer,
    pub(super) prepared: Option<Kind>,
    pub(super) stored: u16,
    pub(super) first_recovery: bool,
    pub(super) terminal_recovery: bool,
    pub(super) disposition: Option<DispositionShape>,
    pub(super) settlement: bool,
    pub(super) reply: bool,
    pub(super) completed: bool,
    pub(super) artifact_claim: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DispositionShape {
    Accepted,
    FullClosed,
    RootOnlyPreparedClosed,
}

impl CheckpointFacts {
    pub(super) fn read(record: &Record) -> Result<Self, LedgerFormatErrorV1> {
        let mut stored = 0;
        let mut first_recovery = false;
        let mut terminal_recovery = false;
        for control in record.suffix.controls() {
            stored |= 1 << control.kind() as u8;
            if control.kind() == Kind::RootRecoveryQuery {
                match evidence::query(control.prepared())?.mode {
                    Mode::SettleRecordedDisposition => first_recovery = true,
                    Mode::RecordRootTerminal => terminal_recovery = true,
                    Mode::Observe => {
                        return Err(corrupt("held Source recovery requires recorded disposition"));
                    }
                }
            }
        }
        let disposition = evidence::root_disposition(record)?.map(|root| {
            if root.disposition == NativeHeldDispositionV1::Accepted {
                DispositionShape::Accepted
            } else if root.scope.is_root_only()
                && root.observation == RootNativeObservationV1::PreparedOnly
            {
                DispositionShape::RootOnlyPreparedClosed
            } else {
                DispositionShape::FullClosed
            }
        });

        Ok(Self {
            phase: record.suffix.phase(),
            outer: record.original.state,
            prepared: record.suffix.prepared().map(|value| value.kind()),
            stored,
            first_recovery,
            terminal_recovery,
            disposition,
            settlement: evidence::storage_assertion(record)?.is_some(),
            reply: record.original.accepted_reply.is_some(),
            // CleanupRequired can also be the retired unleased cold original.
            // That shape is terminal10 with zero A; in-flight cleanup markers
            // and hot terminal archives retain genuine Complete scheduling.
            completed: record.original.state == Outer::Active
                || (record.original.state == Outer::CleanupRequired
                    && (record.suffix.phase() < 10
                        || evidence::artifact(record)?.as_bytes() != &[0; 32])),
            artifact_claim: evidence::has_artifact_claim(record),
        })
    }

    pub(super) fn has(self, kind: Kind) -> bool {
        self.stored & (1 << kind as u8) != 0
    }
}

pub(super) fn permits_checkpoint_phases(
    step: SourceNativeHeldStepV1,
    phases: (u8, u8),
) -> bool {
    use SourceNativeHeldStepV1 as Step;
    match step {
        Step::ChallengeIssued => phases == (0, 1),
        Step::StoragePrepared => phases == (1, 2),
        Step::ChallengeSpent => phases == (2, 3),
        Step::CompletionCommitted => phases == (3, 4),
        Step::HeldPrepared => phases == (4, 5),
        Step::HeldStored => phases == (5, 6),
        Step::RootDispositionPrepared => matches!(phases, (0..=6, 7)),
        Step::RootRecoveryRecorded => matches!(phases, (0..=6, 7) | (7, 7) | (8, 8) | (9, 9)),
        Step::RelayStored => phases == (7, 7),
        Step::StorageSettlementRecorded => phases == (7, 8),
        Step::ProviderSettledPrepared => phases == (8, 8),
        Step::ProviderSettledStored => phases == (8, 9),
        Step::StorageRecoveryPrepared | Step::StorageRecoveryQueryStored => {
            matches!(phases, (7, 7) | (8, 8) | (9, 9))
        }
        Step::StorageRecoveryRecorded => matches!(phases, (7, 8) | (8, 8) | (9, 9)),
        Step::ProviderRecoveryPrepared => matches!(phases, (8, 8) | (9, 9)),
        Step::ProviderRecoveryStored => matches!(phases, (8, 9) | (9, 9)),
        Step::RootTerminalRecorded => phases == (9, 10),
        Step::Requested => false,
    }
}

pub(super) fn permits_hot_checkpoint(outer: Outer, step: SourceNativeHeldStepV1) -> bool {
    outer != Outer::CleanupRequired
        || matches!(
            step,
            SourceNativeHeldStepV1::RootRecoveryRecorded
                | SourceNativeHeldStepV1::StorageRecoveryPrepared
                | SourceNativeHeldStepV1::StorageRecoveryQueryStored
                | SourceNativeHeldStepV1::StorageRecoveryRecorded
                | SourceNativeHeldStepV1::ProviderRecoveryPrepared
                | SourceNativeHeldStepV1::ProviderRecoveryStored
                | SourceNativeHeldStepV1::RootTerminalRecorded
        )
}

pub(super) fn permits_preparation_rotation(
    before: &CheckpointFacts,
    step: SourceNativeHeldStepV1,
    phases: (u8, u8),
) -> bool {
    match (step, before.prepared) {
        (SourceNativeHeldStepV1::ProviderRecoveryPrepared, Some(Kind::ProviderSettled)) => true,
        (SourceNativeHeldStepV1::StorageRecoveryPrepared, Some(Kind::ProviderRelay)) => {
            // Case A preserves unescaped5 at first9 and rotates only after it.
            phases == (7, 7)
                && !before.has(Kind::ProviderRelay)
                && (before.has(Kind::RootAccepted) || before.has(Kind::RootClosed))
                && before.first_recovery
        }
        _ => false,
    }
}

pub(super) fn permits_unescaped_held_clear_shape(
    before: &CheckpointFacts,
    phases: (u8, u8),
) -> bool {
    phases == (5, 7)
        && matches!(before.outer, Outer::Active | Outer::CleanupRequired)
        && before.prepared == Some(Kind::ProviderHeld)
        && !before.has(Kind::ProviderHeld)
        && before.disposition.is_none()
}

pub(super) fn preparation_kind(step: SourceNativeHeldStepV1) -> Option<Kind> {
    use SourceNativeHeldStepV1 as Step;
    match step {
        Step::HeldPrepared => Some(Kind::ProviderHeld),
        Step::ProviderSettledPrepared => Some(Kind::ProviderSettled),
        Step::StorageRecoveryPrepared => Some(Kind::ProviderStorageRecoveryQuery),
        Step::ProviderRecoveryPrepared => Some(Kind::ProviderRecoveryState),
        _ => None,
    }
}

pub(super) fn stored_preparation_kind(step: SourceNativeHeldStepV1) -> Option<Kind> {
    use SourceNativeHeldStepV1 as Step;
    match step {
        Step::HeldStored => Some(Kind::ProviderHeld),
        Step::RelayStored => Some(Kind::ProviderRelay),
        Step::ProviderSettledStored => Some(Kind::ProviderSettled),
        Step::StorageRecoveryQueryStored => Some(Kind::ProviderStorageRecoveryQuery),
        Step::ProviderRecoveryStored => Some(Kind::ProviderRecoveryState),
        _ => None,
    }
}

/// Enumerates schema shapes using the same phase/preparation predicates as validation.
///
/// Unknown first signed proofs are possibilities, never received artifacts. The
/// concrete proposal path still checks their complete assertions and witnesses.
pub(super) fn checkpoint_successors(
    before: CheckpointFacts,
) -> Vec<(SourceNativeHeldStepV1, CheckpointFacts)> {
    use SourceNativeHeldStepV1 as Step;
    const STEPS: [Step; 18] = [
        Step::ChallengeIssued,
        Step::StoragePrepared,
        Step::ChallengeSpent,
        Step::CompletionCommitted,
        Step::HeldPrepared,
        Step::HeldStored,
        Step::RootDispositionPrepared,
        Step::RelayStored,
        Step::StorageSettlementRecorded,
        Step::ProviderSettledPrepared,
        Step::ProviderSettledStored,
        Step::RootRecoveryRecorded,
        Step::StorageRecoveryPrepared,
        Step::StorageRecoveryQueryStored,
        Step::StorageRecoveryRecorded,
        Step::ProviderRecoveryPrepared,
        Step::ProviderRecoveryStored,
        Step::RootTerminalRecorded,
    ];
    let mut successors = Vec::new();
    for step in STEPS {
        if !permits_hot_checkpoint(before.outer, step) {
            continue;
        }
        if before.first_recovery
            && matches!(
                step,
                Step::RelayStored | Step::ProviderSettledPrepared | Step::ProviderSettledStored
            )
        {
            continue;
        }
        let mut next = before;
        next.phase = match step {
            Step::ChallengeIssued => 1,
            Step::StoragePrepared => 2,
            Step::ChallengeSpent => 3,
            Step::CompletionCommitted => 4,
            Step::HeldPrepared => 5,
            Step::HeldStored => 6,
            Step::RootDispositionPrepared => 7,
            Step::RootRecoveryRecorded => before.phase.max(7),
            Step::StorageSettlementRecorded | Step::StorageRecoveryRecorded => before.phase.max(8),
            Step::ProviderSettledStored | Step::ProviderRecoveryStored => 9,
            Step::RootTerminalRecorded => 10,
            _ => before.phase,
        };
        let phases = (before.phase, next.phase);
        if !permits_checkpoint_phases(step, phases) {
            continue;
        }

        if let Some(kind) = preparation_kind(step) {
            let has_predecessor = match step {
                Step::HeldPrepared => before.has(Kind::StorageHeld),
                Step::ProviderSettledPrepared => before.settlement,
                Step::StorageRecoveryPrepared => before.first_recovery,
                Step::ProviderRecoveryPrepared => {
                    before.first_recovery
                        && before.settlement
                        && !(before.completed
                            && before.has(Kind::ProviderSettled)
                            && !before.artifact_claim)
                }
                _ => false,
            };
            if !has_predecessor
                || before.has(kind)
                || (before.prepared.is_some() && !permits_preparation_rotation(&before, step, phases))
            {
                continue;
            }
            next.prepared = Some(kind);
            if matches!(kind, Kind::ProviderHeld | Kind::ProviderRecoveryState) {
                next.artifact_claim = true;
            }
        } else if let Some(kind) = stored_preparation_kind(step) {
            if before.prepared != Some(kind) || before.has(kind) {
                continue;
            }
            next.prepared = None;
            next.stored |= 1 << kind as u8;
        } else {
            match step {
                Step::StoragePrepared => {
                    if before.has(Kind::StorageHeld) || before.prepared.is_some() {
                        continue;
                    }
                    next.stored |= 1 << Kind::StorageHeld as u8;
                    next.reply = true;
                    next.outer = Outer::Prepared;
                }
                Step::CompletionCommitted => {
                    next.outer = Outer::Active;
                    next.completed = true;
                }
                Step::RootDispositionPrepared => {
                    if before.disposition.is_some()
                        || before.prepared.is_some_and(|kind| kind != Kind::ProviderHeld)
                    {
                        continue;
                    }
                    // Full disposition needs actual hot3; an earlier Closed
                    // possibility is the separate Root-only PreparedOnly shape.
                    let choices: &[DispositionShape] = if before.has(Kind::ProviderHeld) {
                        &[
                            DispositionShape::Accepted,
                            DispositionShape::FullClosed,
                            DispositionShape::RootOnlyPreparedClosed,
                        ]
                    } else {
                        &[DispositionShape::RootOnlyPreparedClosed]
                    };
                    for disposition in choices {
                        let mut chosen = next;
                        chosen.disposition = Some(*disposition);
                        chosen.prepared = Some(Kind::ProviderRelay);
                        chosen.artifact_claim =
                            before.has(Kind::ProviderHeld) || before.has(Kind::ProviderRecoveryState);
                        chosen.stored |= 1 << if *disposition == DispositionShape::Accepted {
                            Kind::RootAccepted as u8
                        } else {
                            Kind::RootClosed as u8
                        };
                        successors.push((step, chosen));
                    }
                    continue;
                }
                Step::RootRecoveryRecorded => {
                    if before.first_recovery {
                        continue;
                    }
                    if before.prepared == Some(Kind::ProviderHeld) {
                        if !permits_unescaped_held_clear_shape(&before, phases) {
                            continue;
                        }
                        next.prepared = None;
                        next.artifact_claim =
                            before.has(Kind::ProviderHeld) || before.has(Kind::ProviderRecoveryState);
                    }
                    next.first_recovery = true;
                    next.stored |= 1 << Kind::RootRecoveryQuery as u8;
                    if before.disposition.is_none() && before.has(Kind::ProviderHeld) {
                        for disposition in [
                            DispositionShape::Accepted,
                            DispositionShape::FullClosed,
                            DispositionShape::RootOnlyPreparedClosed,
                        ] {
                            let mut chosen = next;
                            chosen.disposition = Some(disposition);
                            successors.push((step, chosen));
                        }
                        continue;
                    }
                    next.disposition = before
                        .disposition
                        .or(Some(DispositionShape::RootOnlyPreparedClosed));
                }
                Step::StorageSettlementRecorded => {
                    if !before.has(Kind::ProviderRelay)
                        || !before.reply
                        || before.has(Kind::StorageSettled)
                    {
                        continue;
                    }
                    next.stored |= 1 << Kind::StorageSettled as u8;
                    next.settlement = true;
                }
                Step::StorageRecoveryRecorded => {
                    if !before.has(Kind::ProviderStorageRecoveryQuery)
                        || before.has(Kind::StorageRecoveryState)
                    {
                        continue;
                    }
                    next.stored |= 1 << Kind::StorageRecoveryState as u8;
                    // Phase8+ requires an exact child assertion. The eventual
                    // real reducer must join it to the immutable settlement.
                    next.settlement = true;
                }
                Step::RootTerminalRecorded => {
                    if before.prepared.is_some()
                        || !before.settlement
                        || (!before.has(Kind::ProviderSettled)
                            && !before.has(Kind::ProviderRecoveryState))
                        || (before.completed && !before.artifact_claim)
                    {
                        continue;
                    }
                    let mut ack = next;
                    ack.stored |= 1 << Kind::RootTerminalRecorded as u8;
                    successors.push((step, ack));
                    if !before.terminal_recovery {
                        next.terminal_recovery = true;
                        next.stored |= 1 << Kind::RootRecoveryQuery as u8;
                    } else {
                        continue;
                    }
                }
                _ => {}
            }
        }
        successors.push((step, next));
    }
    successors
}

// Case B discards unescaped3 only for a first Root PreparedOnly Closed9. The
// full before graph already derived its nonzero A from the exact Complete rows.
fn permits_unescaped_held_clear(
    before: &Record,
    after: &Record,
    phases: (u8, u8),
) -> Result<bool, LedgerFormatErrorV1> {
    if !permits_unescaped_held_clear_shape(&CheckpointFacts::read(before)?, phases)
        || after.suffix.prepared().is_some()
    {
        return Ok(false);
    }
    Ok(
        evidence::root_disposition(after)?.is_some_and(|disposition| {
            disposition.disposition == NativeHeldDispositionV1::Closed
                && disposition.observation == RootNativeObservationV1::PreparedOnly
                && disposition.scope.is_root_only()
        }),
    )
}

fn require_added(
    controls: &[aos_sandbox_source_provider_protocol::native_held_completion::frame::SignedNativeHeldControlV1],
    legal: impl FnOnce(Kind) -> bool,
) -> Result<(), LedgerFormatErrorV1> {
    if controls.len() != 1 || !legal(controls[0].kind()) {
        return Err(corrupt("held exact first archive"));
    }
    Ok(())
}

pub(super) fn validate_recovery_before(
    control: &PreparedNativeHeldControlV1,
    before: &Records,
    record: &Record,
    previous: Option<&Record>,
) -> Result<(), LedgerFormatErrorV1> {
    if control.kind() != Kind::ProviderRecoveryState {
        return Ok(());
    }
    let state = ProviderNativeRecoveryStateV1::from_canonical_bytes(evidence::required(
        control,
        Tag::ProviderRecoveryState,
    )?)
    .map_err(schema_error)?;
    let previous = previous.ok_or(corrupt("held recovery before row missing"))?;
    let key = native_completion::native_completion_key_v2(record.original.acquisition_id);
    let bytes = before
        .get(&key)
        .ok_or(corrupt("held recovery native before missing"))?;
    if state.fields.phase != previous.suffix.phase()
        || state.fields.acceptance != evidence::acceptance(previous)?
        || state.fields.disposition != evidence::root_disposition(previous)?
        || state.fields.hot_terminal.as_deref()
            != previous
                .suffix
                .control(Kind::ProviderSettled)
                .map(|value| value.to_canonical_bytes())
                .as_deref()
        || state.fields.child.as_deref()
            != previous
                .suffix
                .control(Kind::StorageRecoveryState)
                .map(|value| value.to_canonical_bytes())
                .as_deref()
    {
        return Err(corrupt("held recovery actual before fields"));
    }
    graph::require_witness(
        state
            .fields
            .witness
            .as_ref()
            .ok_or(corrupt("held recovery before witness missing"))?,
        aos_sandbox_source_provider_protocol::native_held_completion::witness::NativeHeldRecordFamilyV1::ProviderNative,
        &key,
        Some(bytes),
    )
}

pub(crate) fn exact_mutations(
    before: &Records,
    after: &Records,
    expected: &BTreeSet<Vec<u8>>,
) -> Result<Vec<SourceNativeHeldMutationV1>, LedgerFormatErrorV1> {
    let changed: BTreeSet<_> = before
        .keys()
        .chain(after.keys())
        .filter(|key| before.get(*key) != after.get(*key))
        .cloned()
        .collect();
    if &changed != expected {
        return Err(corrupt("held exact canonical mutation set"));
    }
    expected
        .iter()
        .map(|key| {
            let after = after
                .get(key)
                .ok_or(corrupt("held checkpoint deleted row"))?
                .clone();
            Ok(SourceNativeHeldMutationV1 {
                key: key.clone(),
                before: before.get(key).cloned(),
                after,
            })
        })
        .collect()
}
