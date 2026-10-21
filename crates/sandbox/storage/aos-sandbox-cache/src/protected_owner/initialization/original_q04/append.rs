//! Suspends the real ordinary Q04 append at the full upper Root crossing.
//!
//! The sole native factory borrows the existing Hold, exact recipe transaction
//! and genuine Root loan. The upper invokes the existing shared append schedule
//! with these finite stage methods; native preparation, interlock, publication
//! and disposal still delegate to the one private CacheAppendContext.

use super::*;
use crate::journal::append::CacheAppendContextV1;
use crate::journal::{CacheMutationGateV1, CommitResult, JournalError, JournalTransaction};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Ready,
    Prepared,
    Coordinates,
    Preflighted,
    GuardHeld,
    FinalReady,
    Appended,
    Applied,
    Published,
    Marked,
    SuccessorOwned,
    Finished,
}

/// Binds the actual ordinary gate to this one borrowed Hold append.
pub struct CacheQ04AppendGateV1 {
    original: usize,
    gate: CacheMutationGateV1<'static>,
}

/// Retains the same ordinary interlock through the shared append schedule.
pub struct CacheQ04AppendGuardV1 {
    _original: Option<Journal>,
}

/// Holds the real prepared stage across the full upper final Root check.
///
/// There is no public constructor, Journal getter or supplied-parts adopter.
/// The same actual Root borrower remains held until this context is retired.
pub struct CacheQ04AppendContextV1<'append, 'flight, 'profile, 'cut> {
    core: CacheAppendContextV1<'append, 'append>,
    _root: &'append ControllerRootQ04CacheLoanV1<'flight, 'profile, 'cut>,
    transaction: &'append JournalTransaction,
    committed: &'append mut Option<Result<CommitResult, CacheQ04ErrorV1>>,
    failed_commit: &'append mut Option<usize>,
    index: usize,
    original: usize,
    settling: Option<[u8; 32]>,
    stage: Stage,
    coordinates: Option<(u64, u64)>,
    durable_bytes: Option<u64>,
}

impl CacheQ04AppendContextV1<'_, '_, '_, '_> {
    fn require_stage(&self, expected: Stage) -> Result<(), JournalError> {
        if self.stage != expected {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    fn require_gate(&self, gate: &CacheQ04AppendGateV1) -> Result<(), JournalError> {
        if gate.original != self.original {
            return Err(JournalError::boundary());
        }
        Ok(())
    }

    /// Prepares the same exact native transaction at the original first stage.
    ///
    /// # Errors
    /// Preserves preparation failure and refuses a substituted transaction.
    pub fn prepare(&mut self, transaction: &JournalTransaction) -> Result<(), JournalError> {
        self.require_stage(Stage::Ready)?;
        if !std::ptr::eq(transaction, self.transaction) {
            return Err(JournalError::boundary());
        }
        self.core.prepare(self.transaction)?;
        self.stage = Stage::Prepared;
        Ok(())
    }

    /// Returns the actual prepared stage's materialized-byte bound.
    #[must_use]
    pub fn projected_materialized_bytes(&self) -> Option<usize> {
        if self.stage != Stage::Prepared {
            return None;
        }
        self.core.projected_materialized_bytes()
    }

    /// Computes and retains the original COMMIT and following NEXT coordinates.
    ///
    /// # Errors
    /// Preserves sequence failure and refuses a skipped or repeated stage.
    pub fn coordinates(&mut self) -> Result<(u64, u64), JournalError> {
        self.require_stage(Stage::Prepared)?;
        let coordinates = self.core.coordinates()?;
        self.coordinates = Some(coordinates);
        self.stage = Stage::Coordinates;
        Ok(coordinates)
    }

    /// Runs the same post-coordinate, expected-length and reserved-capacity checks.
    ///
    /// # Errors
    /// Retains the original native length/capacity refusal without appending.
    pub fn preflight_native_once_v1(
        &mut self,
        materialized_bytes: usize,
        following_sequence: u64,
    ) -> Result<(), JournalError> {
        self.require_stage(Stage::Coordinates)?;
        if self.coordinates.map(|value| value.1) != Some(following_sequence)
            || self.core.projected_materialized_bytes() != Some(materialized_bytes)
        {
            return Err(JournalError::boundary());
        }
        crate::journal::policy::validate_after_coordinates(
            self.core.journal(),
            self.transaction,
            following_sequence,
        )?;
        let expected_length = self.core.expected_length()?;
        crate::journal::policy::validate_after_expected_length(
            self.core.journal(),
            self.transaction,
            self.settling,
            materialized_bytes,
            expected_length,
        )?;
        self.stage = Stage::Preflighted;
        Ok(())
    }

    /// Acquires the same real interlock immediately before the upper Root check.
    ///
    /// # Errors
    /// Preserves the native guard refusal and rejects a foreign gate.
    pub fn before_cache_append(
        &mut self,
        gate: &mut CacheQ04AppendGateV1,
    ) -> Result<CacheQ04AppendGuardV1, JournalError> {
        self.require_stage(Stage::Preflighted)?;
        self.require_gate(gate)?;
        let original = self.core.before_cache_append(&mut gate.gate)?;
        self.stage = Stage::GuardHeld;
        Ok(CacheQ04AppendGuardV1 {
            _original: original,
        })
    }

    /// Resumes the held native stage after the actual full upper Root crossing.
    ///
    /// This performs no extra peer, clock or native currentness observation.
    ///
    /// # Errors
    /// Refuses any stage other than the one fixed held-guard seam.
    pub fn finish_final_crossing_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::GuardHeld)?;
        self.stage = Stage::FinalReady;
        Ok(())
    }

    /// Appends through the sole existing native writer at the original frontier.
    ///
    /// # Errors
    /// Preserves the actual append failure and rejects an unentered crossing.
    pub fn append(&mut self) -> Result<u64, JournalError> {
        self.require_stage(Stage::FinalReady)?;
        let bytes = self.core.append()?;
        self.durable_bytes = Some(bytes);
        self.stage = Stage::Appended;
        Ok(bytes)
    }

    /// Applies the next real prepared record through the same native stage.
    ///
    /// # Errors
    /// Preserves actual apply failure or an incorrect stage.
    pub fn apply_next_record(&mut self) -> Result<bool, JournalError> {
        self.require_stage(Stage::Appended)?;
        let more = self.core.apply_next_record()?;
        if !more {
            self.stage = Stage::Applied;
        }
        Ok(more)
    }

    /// Publishes the actual stage after all real records were applied.
    ///
    /// # Errors
    /// Preserves publication failure and refuses incomplete application.
    pub fn publish(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::Applied)?;
        self.core.publish()?;
        self.stage = Stage::Published;
        Ok(())
    }

    /// Marks actual Q04 history in the same writer's retained Cold remainder.
    ///
    /// # Errors
    /// Refuses any position before the actual native state was published.
    pub fn mark_q04(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::Published)?;
        self.core.mark_q04(self.transaction);
        self.stage = Stage::Marked;
        Ok(())
    }

    /// Rejoins the same gate to the actual committed coordinates and bytes.
    ///
    /// # Errors
    /// Refuses any substituted gate, transaction, NEXT or durable byte count.
    pub fn own_cache_successor(
        &mut self,
        gate: &mut CacheQ04AppendGateV1,
        transaction: &JournalTransaction,
        following_sequence: u64,
        durable_bytes: u64,
    ) -> Result<(), JournalError> {
        self.require_stage(Stage::Marked)?;
        self.require_gate(gate)?;
        if !std::ptr::eq(transaction, self.transaction)
            || self.coordinates.map(|value| value.1) != Some(following_sequence)
            || self.durable_bytes != Some(durable_bytes)
        {
            return Err(JournalError::boundary());
        }
        self.core.own_cache_successor(
            &mut gate.gate,
            self.transaction,
            following_sequence,
            durable_bytes,
        )?;
        self.stage = Stage::SuccessorOwned;
        Ok(())
    }

    /// Poisons the same native writer after ambiguous successor publication.
    pub fn poison(&mut self) {
        self.core.poison();
    }

    /// Finishes the same ordinary native stage after successor ownership.
    ///
    /// # Errors
    /// Preserves the original finish cause and refuses a skipped stage.
    pub fn finish_ordinary(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::SuccessorOwned)?;
        self.core.finish_ordinary()?;
        self.stage = Stage::Finished;
        Ok(())
    }

    /// Drops the stage only after the shared schedule has dropped its real guard.
    pub fn drop_stage(&mut self) {
        self.core.drop_stage();
    }

    /// Parks the actual append outcome before any outer native or Root post.
    ///
    /// A supplied positive outcome cannot skip any real native stage.
    ///
    /// # Errors
    /// Retains the full native error or rejects substituted completion DATA.
    pub fn retain_result_once_v1(
        self,
        result: Result<CommitResult, JournalError>,
    ) -> Result<(), ()> {
        let result = match result {
            Ok(committed)
                if self.stage == Stage::Finished
                    && self.coordinates.map(|value| value.0) == Some(committed.commit_sequence)
                    && self.durable_bytes == Some(committed.durable_bytes) =>
            {
                Ok(committed)
            }
            Ok(_) => Err(JournalError::boundary()),
            Err(cause) => Err(cause),
        };
        let failed = result.is_err();
        *self.committed = Some(result.map_err(CacheQ04ErrorV1::from));
        if failed {
            *self.failed_commit = Some(self.index);
            return Err(());
        }
        Ok(())
    }
}

pub(crate) fn receiving_control_bytes_v1() -> Option<usize> {
    type Parts<'a, 'f, 'p, 'c> = (
        &'a JournalTransaction,
        CacheQ04AppendContextV1<'a, 'f, 'p, 'c>,
        CacheQ04AppendGateV1,
    );
    // The immediate preparation closure captures these three actual places;
    // tuple/Result returns below contain their output, not this environment.
    let preparation_capture = std::mem::size_of::<(
        &Journal, &crate::journal::CacheQ04TransactionRecipesV1<'_>, &usize,
    )>();
    std::mem::size_of::<Parts<'_, '_, '_, '_>>()
        .checked_mul(2)?
        .checked_add(std::mem::size_of::<Result<Parts<'_, '_, '_, '_>, ()>>())?
        .checked_add(std::mem::size_of::<CacheAppendContextV1<'_, '_>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<CacheQ04AppendGuardV1>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<
            Result<CacheQ04AppendGuardV1, JournalError>,
        >())?
        .checked_add(std::mem::size_of::<Result<Option<Journal>, JournalError>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<Result<CommitResult, JournalError>>().checked_mul(2)?)?
        .checked_add(std::mem::size_of::<Result<(), JournalError>>().checked_mul(3)?)?
        .checked_add(std::mem::size_of::<Result<(), ()>>().checked_mul(2)?)?
        // The finite factory's preparation closure has a concrete tuple
        // constructor, Result return and caller tuple before context assembly.
        .checked_add(
            std::mem::size_of::<(&JournalTransaction, Option<[u8; 32]>)>().checked_mul(2)?,
        )?
        .checked_add(std::mem::size_of::<
            Result<(&JournalTransaction, Option<[u8; 32]>), CacheQ04ErrorV1>,
        >())?
        .checked_add(std::mem::size_of::<bool>())?
        .checked_add(preparation_capture.checked_mul(2)?)
}

impl<'step, 'owner, 'flight, 'profile, 'cut>
    CacheQ04AppendOriginalBorrowV1<'step, 'owner, 'flight, 'profile, 'cut>
{
    /// Borrows the real prepared append context after the full journal-entry gate.
    ///
    /// # Errors
    /// Parks the actual preflight/semantic failure in the original COMMIT slot.
    pub fn begin_append_context_once_v1<'append>(
        &'append mut self,
    ) -> Result<
        (
            &'append JournalTransaction,
            CacheQ04AppendContextV1<'append, 'flight, 'profile, 'cut>,
            CacheQ04AppendGateV1,
        ),
        (),
    > {
        if !self.entered
            || self.context_started
            || self.cache.progress.commits[self.index].is_some()
        {
            self.cache
                .progress
                .first
                .get_or_insert(CacheQ04ErrorV1::ChangedCut);
            return Err(());
        }
        self.context_started = true;
        let prepared = (|| {
            self.cache
                .hold
                .preflight_cache_q04_remaining_v1(self.recipes, self.index)?;
            let transaction = self
                .recipes
                .transactions()
                .get(self.index)
                .ok_or(CacheQ04ErrorV1::ChangedCut)?;
            let settling = crate::journal::policy::validate_before_projection_for_recipe_v1(
                self.cache.hold,
                transaction,
                crate::journal::policy::CacheTransactionRecipeV1::Q04 {
                    recipes: self.recipes,
                    index: self.index,
                },
            )?;
            Ok((transaction, settling))
        })();
        let (transaction, settling) = match prepared {
            Ok(prepared) => prepared,
            Err(cause) => {
                self.cache.progress.commits[self.index] = Some(Err(cause));
                self.cache.progress.failed_commit = Some(self.index);
                return Err(());
            }
        };
        let original = self.cache.hold as *const Journal as usize;
        Ok((
            transaction,
            CacheQ04AppendContextV1 {
                core: CacheAppendContextV1::new(self.cache.hold),
                _root: self.root,
                transaction,
                committed: &mut self.cache.progress.commits[self.index],
                failed_commit: &mut self.cache.progress.failed_commit,
                index: self.index,
                original,
                settling,
                stage: Stage::Ready,
                coordinates: None,
                durable_bytes: None,
            },
            CacheQ04AppendGateV1 {
                original,
                gate: CacheMutationGateV1::Ordinary,
            },
        ))
    }
}
