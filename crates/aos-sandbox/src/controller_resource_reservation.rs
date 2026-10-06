//! Owns the Controller's native shared resource ledger.
//!
//! Account records are inclusive grants: a child grant is reserved once in
//! its immediate parent, while use inside the child consumes that same grant.
//! Native bytes are replay DATA, not a constructor for an allocation permit.
//! Enrollment additionally requires the original image/PID1 producer custody.
//! Ambiguous writes and lost owners remain charged until protected recovery;
//! dropping a handle never establishes physical cleanup.

mod codec;
mod bootstrap;
mod replay;
mod grant;
mod component;
mod preparation;
mod q04;
mod settlement;

pub(crate) use grant::ProjectResourceGrantAttemptV1;
pub use preparation::ProjectPreparationReservationAttemptV1;
pub(crate) use preparation::OriginalPreparationData;
pub(crate) use q04::Q04ResourceTransferV1;
pub(crate) use settlement::Q04TerminalDispositionV1;
pub(crate) use settlement::NativeHistory as ResourceNativeHistoryV1;
pub(crate) const Q04_BANK_MEMBERS: usize = q04::BANK_MEMBERS;

pub use bootstrap::{
    ControllerResourceBankOpeningV1, ControllerResourcePreopenLoanV1,
    ControllerResourcePreopenPostV1,
};
pub use component::{
    StorageComponentEnvelopeLoanV1, StorageComponentEnvelopeOriginalV1, StorageComponentPostV1,
};

use aos_sandbox_core::{AccountingError, ResourceAccount, ResourceVector};
use crate::{JournalRecord, JournalTransaction, RecordNamespace};

// The bootstrap interval is paid by the same original enrollment, not the
// per-operation request. This is observation only and issues no child loan.
pub(crate) fn require_controller_interval(
    bank: &std::sync::Arc<std::sync::Mutex<ControllerResourceBankOpeningV1>>,
    journal: &crate::Journal,
    profile: &crate::normal_root::ProductionControllerNormalRootProfileV1,
) -> Result<(), ResourceReservationErrorV1> {
    bank.lock().map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
        .require_enrolled(journal, profile).map(|_| ())
}

/// Retains the original pair delivered by the existing privileged PID1 owner.
///
/// Capturing the closed roles is not bank enrollment. The bank independently
/// verifies the same image bytes, fixed Controller invocation and producer
/// custody before its first durable write. No caller-FD constructor is exposed.
pub struct ControllerResourceEnrollmentCaptureV1 {
    policy: std::fs::File,
    enrollment: std::fs::File,
    process: u32,
}

impl ControllerResourceEnrollmentCaptureV1 {
    pub(crate) fn from_original_table(
        policy: std::os::fd::OwnedFd,
        enrollment: std::os::fd::OwnedFd,
    ) -> Self {
        Self {
            policy: policy.into(),
            enrollment: enrollment.into(),
            process: std::process::id(),
        }
    }
}

/// Reports missing enrollment, invalid native custody, or exhausted capacity.
#[derive(Debug, thiserror::Error)]
pub enum ResourceReservationErrorV1 {
    /// An original bootstrap file read failed; the owning files remain held.
    #[error(transparent)]
    BootstrapIo(#[from] std::io::Error),
    /// The kernel refused an original descriptor or mount observation.
    #[error(transparent)]
    BootstrapDescriptor(#[from] rustix::io::Errno),
    /// The existing fixed Controller launch or confinement changed.
    #[error(transparent)]
    BootstrapProfile(#[from] crate::normal_root::NormalRootStartupErrorV1),
    /// The existing bounded kernel-boot observation failed.
    #[error(transparent)]
    BootstrapKernel(#[from] aos_sandbox_linux::Error),
    /// The image-owned enrollment producer is absent or no longer held.
    #[error("shared resource enrollment is unavailable")]
    EnrollmentUnavailable,
    /// Complete native replay disagrees with its identities or account heads.
    #[error("shared resource ledger is corrupt")]
    CorruptLedger,
    /// The durable predecessor differs from the same original expected head.
    #[error("shared resource predecessor changed")]
    Conflict,
    /// The sole resource arithmetic rejected the proposed reservation.
    #[error(transparent)]
    Accounting(#[from] AccountingError),
    /// The original protected writer refused or could not durably append.
    #[error(transparent)]
    Journal(#[from] crate::JournalError),
    /// The same current Controller, Source or original Root join failed.
    #[error(transparent)]
    Source(#[from] crate::hierarchy::genesis_profile::SourceGenesisErrorV1),
    /// The same canonical admitted specification could not be rejoined.
    #[error(transparent)]
    Specification(Box<crate::sandbox_spec_state::SandboxSpecStateError>),
    /// The original native history or terminal Q04 borrower changed.
    #[error(transparent)]
    Terminal(Box<crate::policy_compiler::create_q04::CreateQ04ErrorV1>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EnrollmentIdentity {
    node: [u8; 16],
    epoch: [u8; 16],
    boot: [u8; 16],
    invocation: [u8; 16],
    manifest: [u8; 32],
}

// These bytes describe trusted image policy, but are not enrollment custody.
// The producer must additionally own the actual original image FD and epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ImageBootstrapPolicy {
    node: [u8; 16],
    epoch: [u8; 16],
    capacity: ResourceVector,
    baseline: ResourceVector,
    controller: ResourceVector,
    components: ResourceVector,
}

impl ImageBootstrapPolicy {
    fn validate(self) -> Result<(), ResourceReservationErrorV1> {
        if self.node == [0; 16] || self.epoch == [0; 16] {
            return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
        }
        ResourceAccount::from_usage(
            aos_sandbox_core::ResourceCeilings::bounded(self.capacity),
            self.baseline,
            ResourceVector::ZERO,
        )?.reserve(self.controller)?.reserve(self.components)?;
        for envelope in [self.controller, self.components] {
            for dimension in [
                aos_sandbox_core::ResourceDimension::MemoryBytes,
                aos_sandbox_core::ResourceDimension::Pids,
                aos_sandbox_core::ResourceDimension::OpenFiles,
                aos_sandbox_core::ResourceDimension::ConcurrentOperations,
            ] {
                if envelope.get(dimension) == 0 {
                    return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AccountKind {
    Node,
    Controller,
    Components,
    Project,
    Sandbox,
    Operation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AccountHead {
    enrollment: EnrollmentIdentity,
    id: [u8; 16],
    parent: [u8; 16],
    kind: AccountKind,
    generation: u64,
    project: [u8; 16],
    sandbox: [u8; 16],
    tree_revision: [u8; 32],
    baseline: ResourceVector,
    account: ResourceAccount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimState {
    Reserved,
    Committed,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimPurpose {
    ControllerBootstrap,
    ComponentEnvelope,
    InclusiveGrant,
    Snapshot,
    ProjectPreparation,
    Q04Preparation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimCut {
    BootLifetime,
    Operation {
        original_wall_seconds: i64,
        original_boottime_nanoseconds: u64,
        deadline_boottime_nanoseconds: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Claim {
    enrollment: EnrollmentIdentity,
    id: [u8; 16],
    account: [u8; 16],
    // A nonzero child names the inclusive grant, not an additional use charge.
    child: [u8; 16],
    owner: [u8; 32],
    purpose: ClaimPurpose,
    operation: [u8; 16],
    project: [u8; 16],
    sandbox: [u8; 16],
    tree_revision: [u8; 32],
    cut: ClaimCut,
    genesis_instance: [u8; 32],
    amount: ResourceVector,
    state: ClaimState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparationBinding {
    claim: Claim,
    nonce: [u8; 16],
    controller_names: crate::journal::ProtectedJournalNamesV1,
    source_names: crate::journal::ProtectedJournalNamesV1,
    source_sequence: u64,
    floor: [u8; 32],
    tree_head: [u8; 32],
    lineage_head: [u8; 32],
}

/// Carries an exact, private bank mutation into the shared append engine.
///
/// Its fields cannot be synthesized by a journal caller. The live bank will
/// create it only while holding its original enrollment and allocation owner.
pub(crate) struct Transition<'original> {
    original: TransitionOriginal<'original>,
    crossing: Option<NativeCrossing<'original>>,
}

struct NativeCrossing<'original> {
    original: aos_sandbox_core::RawPairedClockSample,
    deadline: u64,
    result: &'original std::cell::OnceCell<Result<aos_sandbox_core::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
}

enum TransitionOriginal<'original> {
    Account(&'original AccountTransition),
    Enrollment(&'original bootstrap::EnrollmentTransition),
    Q04(&'original Q04ResourceTransferV1),
}

impl Transition<'_> {
    // Runs only at the shared engine's final pre-append frontier. This is a
    // kernel-only observation: no reentrant Root or Source call holds a lock.
    pub(crate) fn final_crossing(&self) -> Result<(), crate::JournalError> {
        let Some(crossing) = &self.crossing else {
            return match self.original {
                TransitionOriginal::Enrollment(_) => Ok(()),
                TransitionOriginal::Account(_) | TransitionOriginal::Q04(_) =>
                    Err(crate::JournalError::ProtectedBoundary),
            };
        };
        if crossing.result.get().is_some() {
            return Err(crate::JournalError::ProtectedBoundary);
        }
        // The sole initializer is this closed kernel recipe. It cannot call
        // back into this cell; exclusive journal custody excludes another writer.
        let resident = crossing.result.get_or_init(|| {
            crate::policy_compiler::observe_root_first_source_successor_clock_v2(
                Some(crossing.original),
            ).and_then(|sample| {
                if sample.boottime_nanoseconds() >= crossing.deadline {
                    Err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::Stale)
                } else {
                    Ok(sample)
                }
            })
        });
        if resident.is_ok() {
            Ok(())
        } else {
            Err(crate::JournalError::ProtectedBoundary)
        }
    }

    pub(crate) fn require_current(
        &self,
        state: &replay::State,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::JournalError> {
        match self.original {
            TransitionOriginal::Account(original) => original.require_current(state, transaction),
            TransitionOriginal::Enrollment(original) => original.require_current(state, transaction),
            TransitionOriginal::Q04(original) => original.require_current(state, transaction)
                .map_err(|_| crate::JournalError::ProtectedBoundary),
        }
    }
}

struct AccountTransition {
    transaction_id: [u8; 16],
    before: AccountHead,
    after: AccountHead,
    claim: Claim,
    previous_claim: Option<Claim>,
    child: Option<AccountHead>,
    original_clock: Option<aos_sandbox_core::RawPairedClockSample>,
    preparation: Option<PreparationBinding>,
    terminal: Option<settlement::Binding>,
}

impl AccountTransition {
    fn reserve(before: AccountHead, claim: Claim) -> Result<Self, ResourceReservationErrorV1> {
        if claim.enrollment != before.enrollment || claim.account != before.id
            || claim.child != [0; 16] || claim.state != ClaimState::Reserved
            || claim.project != before.project || claim.sandbox != before.sandbox
            || claim.tree_revision != before.tree_revision
            || !matches!((before.kind, claim.purpose),
                (AccountKind::Sandbox, ClaimPurpose::Snapshot)
                | (AccountKind::Project, ClaimPurpose::ProjectPreparation))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let generation = before.generation.checked_add(1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let after = AccountHead {
            generation,
            account: before.account.reserve(claim.amount)?,
            ..before
        };
        Ok(Self {
            transaction_id: aos_sandbox_core::OperationId::new().into_bytes(),
            before,
            after,
            claim,
            previous_claim: None,
            child: None,
            original_clock: None,
            preparation: None,
            terminal: None,
        })
    }

    fn settle(before: AccountHead, previous_claim: Claim, committed: bool) -> Result<Self, ResourceReservationErrorV1> {
        if previous_claim.enrollment != before.enrollment || previous_claim.account != before.id
            || previous_claim.child != [0; 16] || previous_claim.state != ClaimState::Reserved
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let generation = before.generation.checked_add(1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let account = if committed {
            before.account.commit(previous_claim.amount)?
        } else {
            before.account.release_reservation(previous_claim.amount)?
        };
        let claim = Claim {
            state: if committed { ClaimState::Committed } else { ClaimState::Released },
            ..previous_claim
        };
        Ok(Self {
            transaction_id: aos_sandbox_core::OperationId::new().into_bytes(),
            before,
            after: AccountHead { generation, account, ..before },
            claim,
            previous_claim: Some(previous_claim),
            child: None,
            original_clock: None,
            preparation: None,
            terminal: None,
        })
    }

    // The current authority borrower supplies proposed grant DATA. Only this
    // exact immediate-parent transition makes that amount a paid grant.
    fn grant(
        before: AccountHead,
        child: AccountHead,
        claim: Claim,
        original_clock: aos_sandbox_core::RawPairedClockSample,
    ) -> Result<Self, ResourceReservationErrorV1> {
        Self::require_grant_inputs(before, child, claim)?;
        let ClaimCut::Operation {
            original_wall_seconds, original_boottime_nanoseconds,
            deadline_boottime_nanoseconds,
        } = claim.cut else { return Err(ResourceReservationErrorV1::Conflict); };
        if original_clock.host_boot_id() != before.enrollment.boot
            || original_clock.wall_seconds() != original_wall_seconds
            || original_clock.boottime_nanoseconds() != original_boottime_nanoseconds
            || original_boottime_nanoseconds >= deadline_boottime_nanoseconds
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let generation = before.generation.checked_add(1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok(Self {
            transaction_id: aos_sandbox_core::OperationId::new().into_bytes(),
            before,
            after: AccountHead {
                generation,
                account: before.account.reserve(claim.amount)?,
                ..before
            },
            claim,
            previous_claim: None,
            child: Some(child),
            original_clock: Some(original_clock),
            preparation: None,
            terminal: None,
        })
    }

    fn require_grant_inputs(
        before: AccountHead,
        child: AccountHead,
        claim: Claim,
    ) -> Result<(), ResourceReservationErrorV1> {
        if child.enrollment != before.enrollment
            || child.parent != before.id
            || child.generation != 1
            || child.baseline != ResourceVector::ZERO
            || child.account.committed() != ResourceVector::ZERO
            || child.account.reserved() != ResourceVector::ZERO
            || claim.enrollment != before.enrollment
            || claim.account != before.id
            || claim.child != child.id
            || claim.state != ClaimState::Reserved
            || claim.purpose != ClaimPurpose::InclusiveGrant
            || claim.amount != replay::finite_ceilings(child)?
            || claim.project != child.project
            || claim.sandbox != child.sandbox
            || claim.tree_revision != child.tree_revision
            || !replay::allowed_edge(before.kind, child.kind)
            || !matches!(child.kind, AccountKind::Project | AccountKind::Sandbox)
            || (before.kind != AccountKind::Node
                && (before.project != child.project
                    || before.tree_revision != child.tree_revision))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }

        Ok(())
    }

    fn transaction(&self) -> Result<JournalTransaction, ResourceReservationErrorV1> {
        let mut records = vec![
            JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, self.after.id).to_vec(),
                codec::encode_head(self.after)?.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, self.claim.id).to_vec(),
                codec::encode_claim(self.claim)?.to_vec(),
            ),
        ];
        if let Some(child) = self.child {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, child.id).to_vec(),
                codec::encode_head(child)?.to_vec(),
            ));
        }
        if let Some(binding) = self.preparation {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::PREPARATION_PREFIX, binding.claim.id).to_vec(),
                codec::encode_preparation(binding)?.to_vec(),
            ));
        }
        if let Some(binding) = self.terminal {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(settlement::PREFIX, binding.original_id()).to_vec(),
                settlement::encode(binding)?.to_vec(),
            ));
        }
        Ok(JournalTransaction::new(self.transaction_id, records)?)
    }

    pub(crate) fn require_current(
        &self,
        state: &replay::State,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::JournalError> {
        self.require_exact(state, transaction)
            .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    fn require_exact(&self, state: &replay::State, transaction: &JournalTransaction) -> Result<(), ResourceReservationErrorV1> {
        if replay::validate(state)? != Some(self.before.enrollment)
            || replay::find_head(state, self.before.id)? != self.before
            || transaction.id() != &self.transaction_id
            || transaction.records().len() != 2 + usize::from(self.child.is_some())
                + usize::from(self.preparation.is_some())
                + usize::from(self.terminal.is_some())
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let next_generation = self.before.generation.checked_add(1)
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let account = match self.previous_claim {
            None if self.claim.state == ClaimState::Reserved => self.before.account.reserve(self.claim.amount)?,
            Some(previous) if previous.state == ClaimState::Reserved
                && self.claim == (Claim { state: ClaimState::Committed, ..previous }) =>
                    self.before.account.commit(previous.amount)?,
            Some(previous) if previous.state == ClaimState::Reserved
                && self.claim == (Claim { state: ClaimState::Released, ..previous }) =>
                    self.before.account.release_reservation(previous.amount)?,
            _ => return Err(ResourceReservationErrorV1::Conflict),
        };
        if self.after != (AccountHead { generation: next_generation, account, ..self.before }) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let old = replay::record_bytes(state, replay::CLAIM_PREFIX, self.claim.id);
        match (old, self.previous_claim) {
            (None, None) => {}
            (Some(bytes), Some(previous)) if codec::decode_claim(bytes)? == previous => {}
            _ => return Err(ResourceReservationErrorV1::Conflict),
        }
        let head_bytes = codec::encode_head(self.after)?;
        let claim_bytes = codec::encode_claim(self.claim)?;
        let records = transaction.records();
        if !matches_record(&records[0], replay::HEAD_PREFIX, self.after.id, &head_bytes)
            || !matches_record(&records[1], replay::CLAIM_PREFIX, self.claim.id, &claim_bytes)
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if let Some(child) = self.child {
            Self::require_grant_inputs(self.before, child, self.claim)?;
            if self.previous_claim.is_some()
                || replay::has_head(state, child.id)
                || !matches_record(&records[2], replay::HEAD_PREFIX, child.id, &codec::encode_head(child)?)
            {
                return Err(ResourceReservationErrorV1::Conflict);
            }
        } else if self.claim.child != [0; 16] {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        match (self.claim.purpose, self.preparation) {
            (ClaimPurpose::ProjectPreparation, Some(binding))
                if binding.claim == self.claim && self.child.is_none()
                    && self.previous_claim.is_none()
                    && replay::record_bytes(state, replay::PREPARATION_PREFIX, self.claim.id).is_none()
                    && matches_record(&records[2], replay::PREPARATION_PREFIX,
                        self.claim.id, &codec::encode_preparation(binding)?) => {}
            (ClaimPurpose::ProjectPreparation, _) | (_, Some(_)) =>
                return Err(ResourceReservationErrorV1::Conflict),
            (_, None) => {}
        }
        match (self.claim.purpose, self.terminal) {
            (ClaimPurpose::Q04Preparation, Some(binding))
                if self.previous_claim.is_some()
                    && self.child.is_none()
                    && self.preparation.is_none()
                    && replay::record_bytes(state, settlement::PREFIX, binding.original_id()).is_none()
                    && matches_record(&records[2], settlement::PREFIX,
                        binding.original_id(), &settlement::encode(binding)?) => {
                settlement::require_predecessor(state, binding, self)?;
            }
            (ClaimPurpose::Q04Preparation, _) | (_, Some(_)) =>
                return Err(ResourceReservationErrorV1::Conflict),
            (_, None) => {}
        }
        Ok(())
    }
}

fn matches_record(record: &JournalRecord, prefix: u8, id: [u8; 16], bytes: &[u8]) -> bool {
    record.namespace() == RecordNamespace::ControllerResourceReservation
        && record.key() == replay::key(prefix, id)
        && record.value() == Some(bytes)
}

// A native append is not projected to a loan before its complete result and
// independent physical-name post are resident. Both remain owned on failure.
struct ReturnedAppend {
    original: Option<Result<AccountTransition, ResourceReservationErrorV1>>,
    transaction: Option<Result<JournalTransaction, ResourceReservationErrorV1>>,
    names: Option<Result<crate::journal::ProtectedJournalNamesV1, crate::JournalError>>,
    preflight: Option<Result<(), ResourceReservationErrorV1>>,
    native: Option<Result<crate::journal::CommitResult, crate::JournalError>>,
    native_clock: std::cell::OnceCell<Result<aos_sandbox_core::RawPairedClockSample, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>>,
    readback: Option<Result<RecoveredAppend, ResourceReservationErrorV1>>,
    post: Option<Result<(), crate::JournalError>>,
}

impl ReturnedAppend {
    const fn new() -> Self {
        Self {
            original: None,
            transaction: None,
            names: None,
            preflight: None,
            native: None,
            native_clock: std::cell::OnceCell::new(),
            readback: None,
            post: None,
        }
    }

    // The caller parks this owner before it prepares or appends a mutation.
    // An actual native Err is retained; readback cannot overwrite that cause.
    fn append_into(
        &mut self,
        journal: &mut crate::Journal,
        original: Result<AccountTransition, ResourceReservationErrorV1>,
    ) {
        if self.original.is_some() {
            return;
        }
        self.original = Some(original);
        if let Some(Ok(original)) = self.original.as_ref() {
            self.transaction = Some(original.transaction());
        }
        self.names = Some(journal.protected_writer_physical_names_v1());
        if let (Some(Ok(original)), Some(Ok(transaction))) =
            (self.original.as_ref(), self.transaction.as_ref())
        {
            self.preflight = Some(journal.controller_resource_state_v1()
                .map_err(ResourceReservationErrorV1::from)
                .and_then(|state| original.require_exact(state, transaction)));
            if self.names.as_ref().is_some_and(Result::is_ok)
                && self.preflight.as_ref().is_some_and(Result::is_ok)
            {
                self.native = Some(journal.commit_controller_resource_transition_v1(
                    transaction,
                    &Transition {
                        original: TransitionOriginal::Account(original),
                        crossing: match (original.original_clock, original.claim.cut) {
                            (Some(clock), ClaimCut::Operation { deadline_boottime_nanoseconds, .. }) => Some(NativeCrossing {
                                original: clock,
                                deadline: deadline_boottime_nanoseconds,
                                result: &self.native_clock,
                            }),
                            _ => None,
                        },
                    },
                ));
            }
        }

        if self.native.is_some() {
            self.readback = Some(self.recover(journal));
        }
        self.post = Some(journal.validate_held_protected_names());
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().and_then(|result| result.as_ref().err())
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.transaction.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.names.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.preflight.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native_clock.get().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.native.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.readback.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
            .or_else(|| self.post.as_ref().and_then(|result| result.as_ref().err())
                .map(|error| error as &(dyn std::error::Error + 'static)))
    }

    fn require_committed(&self) -> Result<&AccountTransition, ResourceReservationErrorV1> {
        if self.failure().is_some()
            || !matches!(self.native, Some(Ok(_)))
            || !matches!(self.native_clock.get(), Some(Ok(_)))
            || !matches!(self.readback, Some(Ok(RecoveredAppend::Committed)))
            || !matches!(self.post, Some(Ok(())))
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    fn recover(&self, journal: &crate::Journal) -> Result<RecoveredAppend, ResourceReservationErrorV1> {
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let names = self.names.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        if journal.protected_writer_physical_names_v1()? != *names {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let state = journal.controller_resource_state_v1()?;
        if replay::validate(state)? != Some(original.before.enrollment) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let head = replay::find_head(state, original.before.id)?;
        let claim = replay::record_bytes(state, replay::CLAIM_PREFIX, original.claim.id)
            .map(codec::decode_claim).transpose()?;
        let recorded = journal.controller_resource_contains_transaction_v1(
            &original.transaction_id,
        )?;
        if head == original.before && claim == original.previous_claim
            && original.child.is_none_or(|child| !replay::has_head(state, child.id))
            && !recorded
            && original.preparation.is_none_or(|binding|
                replay::record_bytes(state, replay::PREPARATION_PREFIX, binding.claim.id).is_none())
            && original.terminal.is_none_or(|binding|
                replay::record_bytes(state, settlement::PREFIX, binding.original_id()).is_none())
        {
            return Ok(RecoveredAppend::NotCommitted);
        }
        let child_matches = match original.child {
            Some(child) => replay::find_head(state, child.id)? == child,
            None => true,
        };
        if head == original.after && claim == Some(original.claim)
            && child_matches && recorded
        {
            if let Some(binding) = original.preparation {
                let bytes = replay::record_bytes(state, replay::PREPARATION_PREFIX, binding.claim.id)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if codec::decode_preparation(bytes)? != binding {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            if let Some(binding) = original.terminal {
                if binding.names() != *names {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                if let Some(Ok(native)) = self.native.as_ref() {
                    journal.require_q04_returned_commit_v1(native)
                        .map_err(|error| ResourceReservationErrorV1::Terminal(Box::new(error)))?;
                }
                let bytes = replay::record_bytes(state, settlement::PREFIX, binding.original_id())
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if settlement::decode(bytes)? != binding {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                journal.require_controller_resource_history_v1()
                    .map_err(|error| ResourceReservationErrorV1::Terminal(Box::new(error)))?;
            }
            return Ok(RecoveredAppend::Committed);
        }
        Err(ResourceReservationErrorV1::Conflict)
    }
}

enum RecoveredAppend {
    Committed,
    NotCommitted,
}

/// Rejects every generic writer's attempt to modify the private bank.
pub(crate) fn require_transition(
    state: &replay::State,
    transaction: &JournalTransaction,
    transition: Option<&Transition>,
) -> Result<(), crate::JournalError> {
    let selected = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::ControllerResourceReservation
    });
    match (selected, transition) {
        (false, None) => Ok(()),
        (true, Some(original)) => original.require_current(state, transaction),
        _ => Err(crate::JournalError::ProtectedBoundary),
    }
}
