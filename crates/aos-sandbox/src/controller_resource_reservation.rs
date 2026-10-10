//! Owns the Controller's Native resource custody and original-loan transitions.
//!
//! Protocol owns the sole passive bank models, canonical codecs and complete
//! replay. Native originals, returned commits, clocks, enrollment factories and
//! final crossings remain here and are not reconstructed from lower DATA.
//!
//! Account records are inclusive grants: a child grant is reserved once in
//! its immediate parent, while use inside the child consumes that same grant.
//! Native bytes are replay DATA, not a constructor for an allocation permit.
//! Enrollment additionally requires the original image/PID1 producer custody.
//! Ambiguous writes and lost owners remain charged until protected recovery;
//! dropping a handle never establishes physical cleanup.

mod bootstrap;
mod grant;
mod component;
mod root_component;
pub(crate) use root_component::RootReceivingOriginalV1;
mod preparation;
mod q04;
mod settlement;
pub(crate) mod service_interval;
mod nix_intake;
mod q04_intake;

pub(crate) use grant::ProjectResourceGrantAttemptV1;
pub use service_interval::ControllerFirstGlobalPrefixAttemptV1;
pub use nix_intake::NixOriginalStartIntakeAttemptV1;
pub use nix_intake::NixOriginalStartIntakeLoanV1;
pub(crate) use nix_intake::{AcquisitionFailureV1, PaidNixStartOriginalsV1};
pub use preparation::ProjectPreparationReservationAttemptV1;
pub(crate) use preparation::OriginalPreparationData;
pub(crate) use q04::Q04ResourceTransferV1;
pub(crate) use settlement::Q04TerminalDispositionV1;

pub use bootstrap::{
    ControllerResourceBankOpeningV1, ControllerResourcePreopenLoanV1,
    ControllerResourcePreopenPostV1,
};
pub use component::{
    StorageComponentEnvelopeLoanV1, StorageComponentEnvelopeOriginalV1, StorageComponentPostV1,
};

use aos_sandbox_core::{AccountingError, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank::{
    self as bank, AccountHead, AccountKind, AccountMutation, Claim, ClaimCut,
    ClaimPurpose, ClaimState, EnrollmentIdentity, ImageBootstrapPolicy,
    PreparationBinding, TerminalBinding,
};

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;
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

impl From<bank::ResourceBankDataError> for ResourceReservationErrorV1 {
    fn from(error: bank::ResourceBankDataError) -> Self {
        match error {
            bank::ResourceBankDataError::CorruptLedger => Self::CorruptLedger,
            bank::ResourceBankDataError::Conflict => Self::Conflict,
            bank::ResourceBankDataError::EnrollmentUnavailable => Self::EnrollmentUnavailable,
            bank::ResourceBankDataError::Accounting(error) => Self::Accounting(error),
            bank::ResourceBankDataError::Names(error) => Self::Journal(crate::JournalError::from(error)),
            bank::ResourceBankDataError::Transaction(error) => Self::Journal(crate::JournalError::from(error)),
            bank::ResourceBankDataError::Frame(error) => Self::Journal(crate::JournalError::from(error)),
        }
    }
}

/// Compares the original fixed Host policy and PID1 delivery as borrowed DATA.
///
/// The expectations come from the independently measured Host image profile.
/// Success creates neither native enrollment nor an operation reservation.
///
/// # Errors
/// Retains the actual file, kernel, codec or complete-profile binding refusal.
#[doc(hidden)]
pub fn require_original_host_component_pair_v2(
    policy: &std::fs::File,
    enrollment: &std::fs::File,
    expected_node: &[u8; 16],
    expected_epoch: &[u8; 16],
    expected_policy_sha256: &[u8; 32],
    expected_recipient_invocation: &[u8; 16],
    expected_producer_invocation: &[u8; 16],
    expected_host_service: &ResourceVector,
    expected_host_control: &ResourceVector,
) -> Result<(), ResourceReservationErrorV1> {
    let original = bootstrap::observe_original_pair(policy, enrollment)?;
    let host_service = *expected_host_service;
    let host_control = *expected_host_control;
    if !original.identity.matches_host_fields(
        *expected_node, *expected_epoch, *expected_policy_sha256,
        *expected_producer_invocation,
    )
        || original.recipient_invocation != *expected_recipient_invocation
        || !original.policy.host_matches(host_service, host_control)
    {
        return Err(ResourceReservationErrorV1::EnrollmentUnavailable);
    }
    Ok(())
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
            let first_global = matches!(self.original,
                TransitionOriginal::Account(original)
                    if matches!(original.claim.native_fields().purpose,
                        ClaimPurpose::ControllerFirstGlobalPrefix | ClaimPurpose::NixOriginalStartIntake
                            | ClaimPurpose::Q04OriginalIntake));
            let observed = if first_global {
                // This closed boot-lifetime subdivision has no inherited
                // operation's 65-second recipe. Its boot-lifetime first use
                // retains the original pair without inventing a Root deadline.
                crate::policy_compiler::observe_root_first_source_successor_clock_v2(None)
                    .and_then(|sample| {
                        crossing.original.validate_later_sample(sample)
                            .map_err(|_| crate::hierarchy::genesis_profile::SourceGenesisErrorV1::Stale)?;
                        Ok(sample)
                    })
            } else {
                crate::policy_compiler::observe_root_first_source_successor_clock_v2(
                    Some(crossing.original),
                )
            };
            observed.and_then(|sample| {
                if !first_global && sample.boottime_nanoseconds() >= crossing.deadline {
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
        state: &State,
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
    terminal: Option<TerminalBinding>,
}

impl AccountTransition {
    fn reserve(before: AccountHead, claim: Claim) -> Result<Self, ResourceReservationErrorV1> {
        let after = bank::reserve_head(before, claim)
            .map_err(ResourceReservationErrorV1::from)?;
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
        let (after, claim) = bank::settled_pair(before, previous_claim, committed)
            .map_err(ResourceReservationErrorV1::from)?;
        Ok(Self {
            transaction_id: aos_sandbox_core::OperationId::new().into_bytes(),
            before,
            after,
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
        let generation = bank::require_grant_generation(before, child, claim, original_clock)
            .map_err(ResourceReservationErrorV1::from)?;
        Ok(Self {
            transaction_id: aos_sandbox_core::OperationId::new().into_bytes(),
            before,
            after: before.reserve_at_generation(generation, claim.native_fields().amount).map_err(ResourceReservationErrorV1::from)?,
            claim,
            previous_claim: None,
            child: Some(child),
            original_clock: Some(original_clock),
            preparation: None,
            terminal: None,
        })
    }


    fn history(&self) -> AccountMutation<'_> {
        AccountMutation::new((
            &self.transaction_id, &self.before, &self.after, &self.claim,
            &self.previous_claim, &self.child, &self.preparation, &self.terminal,
        ))
    }

    fn transaction(&self) -> Result<JournalTransaction, ResourceReservationErrorV1> {
        self.history().transaction().map_err(ResourceReservationErrorV1::from)
    }

    pub(crate) fn require_current(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), crate::JournalError> {
        self.require_exact(state, transaction)
            .map_err(|_| crate::JournalError::ProtectedBoundary)
    }

    fn require_exact(&self, state: &State, transaction: &JournalTransaction) -> Result<(), ResourceReservationErrorV1> {
        self.history().require_exact(state, transaction).map_err(ResourceReservationErrorV1::from)
    }
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
                        crossing: match (original.original_clock, original.claim.native_fields().cut) {
                            (Some(clock), ClaimCut::BootLifetime)
                                if matches!(original.claim.native_fields().purpose,
                                    ClaimPurpose::ControllerFirstGlobalPrefix | ClaimPurpose::NixOriginalStartIntake
                                        | ClaimPurpose::Q04OriginalIntake) =>
                                Some(NativeCrossing {
                                        original: clock,
                                        deadline: clock.boottime_nanoseconds(),
                                        result: &self.native_clock,
                                    }),
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
        if bank::validate(state).map_err(ResourceReservationErrorV1::from)? != Some(original.before.native_fields().enrollment) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let head = bank::find_head(state, original.before.native_fields().id).map_err(ResourceReservationErrorV1::from)?;
        let claim = bank::claim_bytes(state, original.claim.native_fields().id).map(|bytes| Claim::decode(bytes).map_err(ResourceReservationErrorV1::from)).transpose()?;
        let recorded = journal.controller_resource_contains_transaction_v1(
            &original.transaction_id,
        )?;
        if head == original.before && claim == original.previous_claim
            && original.child.is_none_or(|child| !bank::has_head(state, child.native_fields().id))
            && !recorded
            && original.preparation.is_none_or(|binding|
                bank::preparation_bytes(state, binding.claim().native_fields().id).is_none())
            && original.terminal.is_none_or(|binding|
                bank::terminal_bytes(state, binding.native_fields().original_id).is_none())
        {
            return Ok(RecoveredAppend::NotCommitted);
        }
        let child_matches = match original.child {
            Some(child) => bank::find_head(state, child.native_fields().id).map_err(ResourceReservationErrorV1::from)? == child,
            None => true,
        };
        if head == original.after && claim == Some(original.claim)
            && child_matches && recorded
        {
            if let Some(binding) = original.preparation {
                let bytes = bank::preparation_bytes(state, binding.claim().native_fields().id)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if !binding.matches_canonical(bytes).map_err(ResourceReservationErrorV1::from)? {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
            }
            if let Some(binding) = original.terminal {
                if binding.native_fields().names != *names {
                    return Err(ResourceReservationErrorV1::Conflict);
                }
                if let Some(Ok(native)) = self.native.as_ref() {
                    journal.require_q04_returned_commit_v1(native)
                        .map_err(|error| ResourceReservationErrorV1::Terminal(Box::new(error)))?;
                }
                let bytes = bank::terminal_bytes(state, binding.native_fields().original_id)
                    .ok_or(ResourceReservationErrorV1::Conflict)?;
                if !binding.matches_canonical(bytes).map_err(ResourceReservationErrorV1::from)? {
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
    state: &State,
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
