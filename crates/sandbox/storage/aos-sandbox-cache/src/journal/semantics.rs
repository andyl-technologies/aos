//! Binds Cache's actual captured cursor to the sole full semantic recipe.
//!
//! Cache keeps native opening, names, financial bounds and effect gates in its
//! own originals. The fixed no-history binding cannot adopt a Source challenge
//! witness or construct a Controller, Source, Root or Cache native owner. Every
//! logical COMMIT, materialization/index step, semantic finish and EOF remains
//! in the shared recipe; there is no final-map-only replacement validator.

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1;
use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::{
    CanonicalIndexedReplayErrorV1, CanonicalIndexedReplayV1,
};
use aos_sandbox_broker::controller_receiving::bank_launch::ControllerBankLaunchErrorV1;
use aos_sandbox_model::{ResourceDimension, ResourceVector};

use super::construction::{ConstructionLoanV1, ConstructionOwnerV1};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::domain_ledger::transaction::JournalLimits;

pub(super) mod binding {
    aos_sandbox_ledger_replay::define_cold_replay_binding_v1!();
}

#[derive(Debug, thiserror::Error)]
pub(super) enum CacheReplayStageErrorV1 {
    #[error(transparent)]
    Native(#[from] CanonicalIndexedReplayErrorV1),
    #[error(transparent)]
    Geometry(#[from] CanonicalJournalMechanicalErrorV1),
    #[error(transparent)]
    Receiving(ControllerBankLaunchErrorV1),
    #[error(transparent)]
    Readonly(super::JournalError),
}

pub(super) type CacheSemanticOriginalV1 =
    binding::FixedColdSemanticOriginalV1<CacheReplayStageErrorV1>;

pub(super) type CacheSemanticRemainderV1 =
    aos_sandbox_ledger_replay::cold::ColdReplayRemainderDataV1;

/// Prices the actual shared semantic original before entering its cursor.
///
/// Dynamic prefix/Source/native/index geometry remains charged separately by
/// the real captured opening; this DATA supplier cannot admit any work.
///
/// # Errors
/// Returns the existing checked semantic geometry failure on overflow.
pub(super) fn receiving_demand_v1() -> Result<ResourceVector, CanonicalJournalMechanicalErrorV1> {
    let invalid = || CanonicalJournalMechanicalErrorV1::LimitExceeded("Cache replay controls");
    let controls = std::mem::size_of::<PaidCacheCursorV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, ()>>()
        .checked_mul(2)
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<CacheSemanticRemainderV1>().checked_mul(2)?)
        })
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(invalid)?;
    CacheSemanticOriginalV1::fixed_demand_v1()?
        .checked_add(ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, controls))
        .map_err(|_| invalid())
}

/// Observes the same ordinary no-history schedule used by the old Cache open.
///
/// The actual cursor remains borrowed from the same held native opening. It
/// registers and compares its own index and materializes once. Ordinary family
/// disposition is false, matching the old captured ordinary Journal path; the
/// selected Source/Controller/Root retention policy is not substituted here.
///
/// # Errors
/// Returns a stopping marker while the original retains precise native or
/// semantic causes; the actual caller must still run every owed native post.
pub(super) fn observe_once<P>(
    original: &mut CacheSemanticOriginalV1,
    cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
    identity: FileIdentity,
    limits: JournalLimits,
    loan: &mut ConstructionLoanV1<'_, '_, '_, '_, P>,
    owner: ConstructionOwnerV1,
    native_complete: ResourceVector,
) -> Result<(), ()> {
    let mut paid = PaidCacheCursorV1 {
        cursor,
        receiving: CacheSemanticReceivingV1::Construction {
            loan, owner, native_complete,
        },
    };
    original.observe_ordinary_once(&mut paid, identity, limits, None)
}

/// Moves only the actual completed semantic remainder from that same original.
///
/// No map, file, index, native prefix or successful boolean is accepted. The
/// real caller must finish its native tail/currentness and perform the single
/// native/index transfer before installing this DATA beside its Cache writer.
pub(super) fn take_remainder_once(
    original: &mut CacheSemanticOriginalV1,
) -> Option<CacheSemanticRemainderV1> {
    original
        .take_remainder_once()
        .map(binding::move_cold_remainder_data_v1)
}

// This adapter is private and concrete: it borrows the SAME native cursor and
// one of Cache's two genuine existing construction loans. The common recipe
// calls these two financial frontiers before semantic model growth. Neither a
// callback nor a caller-selected payer can enter a Cache constructor.
enum CacheSemanticReceivingV1<
    'turn, 'borrow, 'writer, 'launch, 'profile, 'funding, 'readonly_profile, 'data, P,
> {
    Construction {
        loan: &'turn mut ConstructionLoanV1<'borrow, 'writer, 'launch, 'profile, P>,
        owner: ConstructionOwnerV1,
        native_complete: ResourceVector,
    },
    Readonly(
        &'turn mut super::readonly_receiving::CacheReadonlyReceivingContextV1<
            'borrow, 'funding, 'readonly_profile, 'data,
        >,
    ),
}

struct PaidCacheCursorV1<
    'turn, 'file, 'cursor, 'borrow, 'writer, 'launch, 'profile, 'funding, 'readonly_profile, 'data, P,
> {
    cursor: &'turn mut CanonicalIndexedReplayV1<'file, 'cursor>,
    receiving: CacheSemanticReceivingV1<
        'turn, 'borrow, 'writer, 'launch, 'profile, 'funding, 'readonly_profile, 'data, P,
    >,
}

impl<P> binding::FixedColdNativeStageV1
    for PaidCacheCursorV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, P>
{
    type Error = CacheReplayStageErrorV1;

    fn prepare_semantic_commit_once(&mut self) -> Result<(), Self::Error> {
        let commit = self.cursor.current_commit()
            .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
        match &mut self.receiving {
            CacheSemanticReceivingV1::Construction { loan, owner, native_complete } => {
                let semantic = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
                    commit.prior_state(), Some(commit.transaction()),
                )?;
                let complete = native_complete.checked_add(semantic).map_err(|_| {
                    CanonicalJournalMechanicalErrorV1::LimitExceeded(
                        "Cache replay semantic representation",
                    )
                })?;
                loan.require_complete_v1(*owner, complete)
                    .map_err(CacheReplayStageErrorV1::Receiving)
            }
            CacheSemanticReceivingV1::Readonly(receiving) => {
                let (begin_sequence, begin_offset) = commit.begin_position();
                // The old readonly adapter observes its suffix BEFORE the
                // semantic debit, at preparation before delete validation.
                receiving.observe_native_commit(
                    commit.transaction(), begin_sequence, commit.commit_sequence(),
                    begin_offset, commit.coordinates().offset,
                ).map_err(CacheReplayStageErrorV1::Readonly)?;
                receiving.before_semantic_replay(
                    commit.prior_state(), Some(commit.transaction()),
                ).map_err(CacheReplayStageErrorV1::Readonly)
            }
        }
    }

    fn prepare_semantic_prefix_once(&mut self) -> Result<(), Self::Error> {
        let prefix = self.cursor.completed_prefix()
            .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
        match &mut self.receiving {
            CacheSemanticReceivingV1::Construction { loan, owner, native_complete } => {
                let semantic = aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
                    prefix.state(), None,
                )?;
                let complete = native_complete.checked_add(semantic).map_err(|_| {
                    CanonicalJournalMechanicalErrorV1::LimitExceeded(
                        "Cache replay semantic representation",
                    )
                })?;
                loan.require_complete_v1(*owner, complete)
                    .map_err(CacheReplayStageErrorV1::Receiving)
            }
            CacheSemanticReceivingV1::Readonly(receiving) => {
                receiving.before_semantic_replay(prefix.state(), None)
                    .map_err(CacheReplayStageErrorV1::Readonly)?;
                let coordinates = prefix.coordinates();
                receiving.finish_native(
                    coordinates.durable_next_sequence, coordinates.durable_end,
                    receiving.captured_end,
                ).map_err(CacheReplayStageErrorV1::Readonly)
            }
        }
    }

fn advance_once(&mut self) -> Result<bool, Self::Error> {
        Ok(self.cursor.advance_once()?)
    }

    fn current_commit(
        &self,
    ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>> {
        self.cursor.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.cursor.validate_compaction_once()?)
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.cursor.register_and_compare_index_once()?)
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.cursor.prepare_change_once()?)
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        Ok(self.cursor.apply_next_record_once()?)
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.cursor.finish_commit_accounting_once()?)
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        Ok(self.cursor.finish_commit_once()?)
    }

    fn completed_prefix(
        &self,
    ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>> {
        self.cursor.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        self.cursor
            .completed_prefix()
            .ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
        Ok(())
    }
}

pub(super) fn observe_readonly_once(
    original: &mut CacheSemanticOriginalV1,
    cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
    identity: FileIdentity,
    limits: JournalLimits,
    receiving: &mut super::readonly_receiving::CacheReadonlyReceivingContextV1<'_, '_, '_, '_>,
) -> Result<(), ()> {
    let mut paid = PaidCacheCursorV1::<()> {
        cursor,
        receiving: CacheSemanticReceivingV1::Readonly(receiving),
    };
    original.observe_ordinary_once(&mut paid, identity, limits, None)
}
