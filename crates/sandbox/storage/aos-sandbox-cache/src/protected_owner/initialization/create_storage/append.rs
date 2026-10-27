//! Lends the actual Hold appender to the upper lexical programme.
//!
//! The private factory takes the existing mutable Hold reference under the
//! genuine native Cache original. Every native stage remains here; the upper
//! programme inserts its real Controller/Source observations at the original
//! transition and final-crossing positions in the one shared append schedule.
//! No writer, guard, map, descriptor, phase result or payer can be adopted.

use super::*;
use crate::journal::append::CacheAppendContextV1;
use crate::journal::{CacheMutationGateV1, JournalError};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Entered,
    TransitionObserved,
    Ready,
    Prepared,
    Coordinates,
    Preflighted,
    GateHeld,
    FinalObserved,
    FinalReady,
    Appended,
    Applied,
    Published,
    SuccessorOwned,
    Finished,
}

/// Keeps the actual ordinary Hold interlock behind its private construction.
pub struct CacheHeldAppendGateV1 {
    original: usize,
    gate: CacheMutationGateV1<'static>,
}

/// Retains the real ordinary guard until the shared schedule retires it.
pub struct CacheHeldAppendGuardV1 {
    _original: Option<Journal>,
}

/// Keeps the same Hold reference, native stage and genuine Cache loan borrowed.
///
/// Only the actual initialized Held producer constructs this owner. Its stage
/// methods enforce the finite native sequence; upper refusal can only close it.
/// The original currentness view contains comparison DATA and no native handle.
pub struct CacheHeldAppendContextV1<'append, 'cache, 'transaction> {
    cache: &'append mut OriginalCreateStorageCacheLoanV1<'cache>,
    context: Option<CacheAppendContextV1<'cache, 'transaction>>,
    released: Option<&'append mut released::CacheReleasedOriginalsV1>,
    transaction: &'transaction JournalTransaction,
    original: usize,
    settling: Option<[u8; 32]>,
    stage: Stage,
    upper_refused: bool,
    coordinates: Option<(u64, u64)>,
    durable_bytes: Option<u64>,
    parked: bool,
}

impl<'append, 'cache, 'transaction> CacheHeldAppendContextV1<'append, 'cache, 'transaction> {
    /// Prices the actual native context, gate and forwarding control planes.
    ///
    /// This counts memory only. It supplies no admission or metadata credit.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<CacheHeldAppendGateV1>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheHeldAppendGuardV1>()))
            // The factory's owned return and caller's retained Result coexist
            // with its constructor local and the destructured caller owners.
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(Self, CacheHeldAppendGateV1), CacheHeldClosedV1>>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<(Self, CacheHeldAppendGateV1)>())
            })
            // Guard construction/return and the lexical caller destination
            // are distinct from the gate and prepared native core stage.
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<CacheHeldAppendGuardV1, JournalError>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<CacheHeldAppendGuardV1>()))
            .and_then(|bytes| {
                bytes.checked_add(std::mem::size_of::<(
                    &mut OriginalCreateStorageCacheLoanV1<'cache>,
                    &Arc<JournalTransaction>,
                    &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
                )>())
            })
            // Held and Released crossing closures are alternative native
            // paths. Their capture constructor and FnOnce receiver coexist
            // with the owned return and the caller's retained Result.
            .and_then(|bytes| {
                let held = std::mem::size_of::<(
                    &Option<Result<CacheCreateStorageReceivingShapeV1, CacheHeldErrorV1>>,
                    &Journal,
                    &bool,
                    &Option<Result<CacheHeldBodyDataV1, CacheHeldErrorV1>>,
                    &Option<Result<Arc<JournalTransaction>, CacheHeldErrorV1>>,
                    &&JournalTransaction,
                )>();
                let released = std::mem::size_of::<(
                    &bool,
                    &OriginalCreateStorageCacheLoanV1<'cache>,
                    &Option<Result<CacheHeldWriterShapeV1, CacheHeldErrorV1>>,
                    &Option<[u8; 16]>,
                    &Journal,
                    &bool,
                    &Option<Result<Arc<JournalTransaction>, CacheHeldErrorV1>>,
                    &&JournalTransaction,
                )>();
                bytes.checked_add(held.max(released).checked_mul(2)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), CacheHeldErrorV1>>().checked_mul(2)?,
                )
            })
            // Each actual factory checks the retained Cache original and
            // identity inside an immediate closure over the same real lender.
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<(
                        &crate::protected_owner::initialization::baseline::CacheConstructionOriginalsV1,
                        &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
                        &CacheHeldIdentityDataV1,
                    )>()
                    .checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), ControllerCacheAuditFundingErrorV1>>()
                        .checked_mul(2)?,
                )
            })
            // These are new opaque forwarding methods around the existing
            // priced native core. Count their constructor, ABI and caller
            // Result planes without credit from the core or resident fields.
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<(
                        // Transition observation/finish, prepare, preflight,
                        // final observation/finish, publish, successor, finish.
                        [Result<(), JournalError>; 9],
                        // Private require_stage, require_native_positive and
                        // require_gate return inside those outer wrappers.
                        [Result<(), JournalError>; 3],
                        Result<u64, JournalError>, // append
                        Result<(u64, u64), JournalError>, // coordinates
                        Result<bool, JournalError>, // apply_next_record
                        Option<usize>, // projected_materialized_bytes
                        Result<(), CacheHeldClosedV1>, // retain_result
                    )>()
                    .checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                // Each of the two currentness frontiers returns through the
                // native original, this wrapper and its actual upper call.
                bytes.checked_add(
                    std::mem::size_of::<CacheHeldCurrentnessOriginalV1<'_>>()
                        .checked_mul(6)?,
                )
            })
            .and_then(|bytes| {
                // Primary closure return, macro expression, outer closure
                // return, actual caller and retain_result's owning argument.
                bytes.checked_add(
                    std::mem::size_of::<Result<CommitResult, JournalError>>()
                        .checked_mul(5)?,
                )
            })
            .and_then(|bytes| {
                // Every borrowed wrapper is bounded by its actual deepest
                // native call chain, with argument and receiver planes. The
                // observation chain alone enters both crossing functions.
                let stage = std::mem::size_of::<(&Self, Stage)>();
                let gate = std::mem::size_of::<(&Self, &CacheHeldAppendGateV1)>();
                let crossing = std::mem::size_of::<(&mut Self, usize, bool)>();
                let observation = std::mem::size_of::<&mut Self>()
                    .checked_add(crossing.checked_mul(2)?)?;
                let successor = std::mem::size_of::<(
                    &mut Self, &mut CacheHeldAppendGateV1, &JournalTransaction, u64, u64,
                )>().checked_add(stage.max(gate))?;
                let preflight = std::mem::size_of::<(&mut Self, usize, u64)>()
                    .checked_add(stage)?;
                let guard = std::mem::size_of::<(&mut Self, &mut CacheHeldAppendGateV1)>()
                    .checked_add(stage.max(gate))?;
                let prepare = std::mem::size_of::<(&mut Self, &JournalTransaction)>()
                    .checked_add(stage)?;
                // Coordinates/append/apply/publish/finish use one receiver
                // and require_stage. Projected/currentness/poison/drop_stage
                // use only their receiver; Drop/restoration uses two.
                let simple = std::mem::size_of::<&mut Self>()
                    .checked_add(stage.max(std::mem::size_of::<&mut Self>()))?;
                let borrowed = observation.max(successor).max(preflight)
                    .max(guard).max(prepare).max(simple).checked_mul(2)?;
                bytes.checked_add(borrowed)
            })
            .and_then(|bytes| {
                // retain_result takes OWNED self. Its move construction, ABI
                // receiver and caller destination are not borrowed references.
                // The separate restoring receiver is in the chain bound above.
                bytes.checked_add(std::mem::size_of::<Self>().checked_mul(3)?)
            })
    }

    /// Borrows this same native association for the actual upper observation.
    pub fn currentness_original_v1(&self) -> CacheHeldCurrentnessOriginalV1<'_> {
        self.cache.currentness_original_v1()
    }

    /// Performs the original native transition checks and all owed bookends.
    ///
    /// # Errors
    /// Reports native debt only after the exact original bookends are retained.
    /// The upper programme must still run its independent currentness observer.
    pub fn observe_transition_native_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::Entered)?;
        self.crossing_native_once(0, true);
        if self.released.is_none() {
            self.cache.progress.currentness_site = Some(CacheHeldCurrentnessSiteV1::Transition);
        }
        self.stage = Stage::TransitionObserved;
        self.require_native_positive()
    }

    /// Permanently fences this append after an actual upper observation fails.
    ///
    /// This refusal grants no stage progression and replaces no native cause.
    pub fn reject_upper_currentness_v1(&mut self) {
        self.upper_refused = true;
    }

    /// Resumes native guards after the first actual upper currentness observer.
    ///
    /// # Errors
    /// Refuses earlier native or upper debt, a repeated frontier, or any of the
    /// original ordinary guards after the CreateStorage transition.
    pub fn finish_transition_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::TransitionObserved)?;
        self.require_native_positive()?;
        let context = self.context.as_ref().ok_or_else(JournalError::boundary)?;
        crate::journal::policy::validate_after_create_storage_transition_v1(
            context.journal(),
            self.transaction,
        )?;
        self.stage = Stage::Ready;
        Ok(())
    }

    /// Prepares the exact retained transaction through the sole native stage.
    ///
    /// # Errors
    /// Preserves the actual native preparation error and refuses stage skips.
    pub fn prepare(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<(), JournalError> {
        self.require_stage(Stage::Ready)?;
        if !std::ptr::eq(transaction, self.transaction) {
            return Err(JournalError::boundary());
        }
        self.context
            .as_mut()
            .ok_or_else(JournalError::boundary)?
            .prepare(transaction)?;
        self.stage = Stage::Prepared;
        Ok(())
    }

    /// Returns the same stage's projected native materialized byte bound.
    #[must_use]
    pub fn projected_materialized_bytes(&self) -> Option<usize> {
        if self.stage != Stage::Prepared {
            return None;
        }
        self.context.as_ref()?.projected_materialized_bytes()
    }

    /// Computes and retains the same native COMMIT and following NEXT.
    ///
    /// # Errors
    /// Preserves sequence refusal and rejects repeated or skipped stages.
    pub fn coordinates(&mut self) -> Result<(u64, u64), JournalError> {
        self.require_stage(Stage::Prepared)?;
        let coordinates = self
            .context
            .as_mut()
            .ok_or_else(JournalError::boundary)?
            .coordinates()?;
        self.coordinates = Some(coordinates);
        self.stage = Stage::Coordinates;
        Ok(coordinates)
    }

    /// Runs the original post-coordinate and complete expected-length checks.
    ///
    /// # Errors
    /// Preserves the original sequence, native length and capacity first cause.
    pub fn preflight_native_once_v1(
        &mut self,
        materialized_bytes: usize,
        following_sequence: u64,
    ) -> Result<(), JournalError> {
        self.require_stage(Stage::Coordinates)?;
        if self.coordinates.map(|value| value.1) != Some(following_sequence) {
            return Err(JournalError::boundary());
        }
        let context = self.context.as_mut().ok_or_else(JournalError::boundary)?;
        if context.projected_materialized_bytes() != Some(materialized_bytes) {
            return Err(JournalError::boundary());
        }
        crate::journal::policy::validate_after_coordinates(
            context.journal(),
            self.transaction,
            following_sequence,
        )?;
        let expected_length = context.expected_length()?;
        crate::journal::policy::validate_after_expected_length(
            context.journal(),
            self.transaction,
            self.settling,
            materialized_bytes,
            expected_length,
        )?;
        self.stage = Stage::Preflighted;
        Ok(())
    }

    /// Retains the actual ordinary interlock at its original lexical frontier.
    ///
    /// # Errors
    /// Preserves the interlock refusal and rejects a foreign or reused token.
    pub fn before_cache_append(
        &mut self,
        gate: &mut CacheHeldAppendGateV1,
    ) -> Result<CacheHeldAppendGuardV1, JournalError> {
        self.require_stage(Stage::Preflighted)?;
        self.require_gate(gate)?;
        let original = self
            .context
            .as_ref()
            .ok_or_else(JournalError::boundary)?
            .before_cache_append(&mut gate.gate)?;
        self.stage = Stage::GateHeld;
        Ok(CacheHeldAppendGuardV1 {
            _original: original,
        })
    }

    /// Performs the final native checks and all independently owed bookends.
    ///
    /// # Errors
    /// Reports native debt after retaining the original post set. An error
    /// cannot suppress the upper final currentness observation.
    pub fn observe_final_native_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::GateHeld)?;
        self.crossing_native_once(1, false);
        if self.released.is_none() {
            self.cache.progress.currentness_site = Some(CacheHeldCurrentnessSiteV1::FinalCrossing);
        }
        self.stage = Stage::FinalObserved;
        self.require_native_positive()
    }

    /// Checks debt after the actual upper final currentness observation.
    ///
    /// # Errors
    /// Refuses native or upper debt and any stage substitution.
    pub fn finish_final_crossing_once_v1(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::FinalObserved)?;
        self.require_native_positive()?;
        self.stage = Stage::FinalReady;
        Ok(())
    }

    /// Appends only after the original native final crossing is complete.
    ///
    /// # Errors
    /// Preserves the actual native append cause and rejects skipped stages.
    pub fn append(&mut self) -> Result<u64, JournalError> {
        self.require_stage(Stage::FinalReady)?;
        let bytes = self
            .context
            .as_mut()
            .ok_or_else(JournalError::boundary)?
            .append()?;
        self.durable_bytes = Some(bytes);
        self.stage = Stage::Appended;
        Ok(bytes)
    }

    /// Applies the next same prepared native record after durable append.
    ///
    /// # Errors
    /// Preserves the actual apply error and rejects preappend or repeated use.
    pub fn apply_next_record(&mut self) -> Result<bool, JournalError> {
        self.require_stage(Stage::Appended)?;
        let more = self
            .context
            .as_mut()
            .ok_or_else(JournalError::boundary)?
            .apply_next_record()?;
        if !more {
            self.stage = Stage::Applied;
        }
        Ok(more)
    }

    /// Publishes the actual prepared native state after all records apply.
    ///
    /// # Errors
    /// Preserves publication failure and rejects incomplete apply.
    pub fn publish(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::Applied)?;
        self.context
            .as_mut()
            .ok_or_else(JournalError::boundary)?
            .publish()?;
        self.stage = Stage::Published;
        Ok(())
    }

    /// Rejoins the same ordinary gate to the actual committed successor.
    ///
    /// # Errors
    /// Rejects a foreign gate, transaction, NEXT or durable byte count.
    pub fn own_cache_successor(
        &mut self,
        gate: &mut CacheHeldAppendGateV1,
        transaction: &JournalTransaction,
        following_sequence: u64,
        durable_bytes: u64,
    ) -> Result<(), JournalError> {
        self.require_stage(Stage::Published)?;
        self.require_gate(gate)?;
        if !std::ptr::eq(transaction, self.transaction)
            || self.coordinates.map(|value| value.1) != Some(following_sequence)
            || self.durable_bytes != Some(durable_bytes)
        {
            return Err(JournalError::boundary());
        }
        self.context
            .as_mut()
            .ok_or_else(JournalError::boundary)?
            .own_cache_successor(
                &mut gate.gate,
                transaction,
                following_sequence,
                durable_bytes,
            )?;
        self.stage = Stage::SuccessorOwned;
        Ok(())
    }

    /// Marks the actual native writer poisoned after ambiguous publication.
    pub fn poison(&mut self) {
        if let Some(context) = self.context.as_mut() {
            context.poison();
        }
    }

    /// Runs the existing ordinary finisher after actual successor ownership.
    ///
    /// # Errors
    /// Preserves the actual finisher error and refuses skipped stages.
    pub fn finish_ordinary(&mut self) -> Result<(), JournalError> {
        self.require_stage(Stage::SuccessorOwned)?;
        self.context
            .as_mut()
            .ok_or_else(JournalError::boundary)?
            .finish_ordinary()?;
        self.stage = Stage::Finished;
        Ok(())
    }

    /// Retires the native stage after the shared schedule drops its real guard.
    pub fn drop_stage(&mut self) {
        if let Some(context) = self.context.as_mut() {
            context.drop_stage();
        }
    }

    /// Parks the actual complete result before restoring the same Hold reference.
    ///
    /// # Errors
    /// Reports the coarse native closure after preserving its actual first
    /// cause. A supplied positive result cannot skip the real native stages.
    pub fn retain_result_once_v1(
        mut self,
        result: Result<CommitResult, JournalError>,
    ) -> Result<(), CacheHeldClosedV1> {
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
        self.restore_reference();
        self.parked = true;
        match self.released.as_deref_mut() {
            Some(released) => {
                released.append = Some(result);
                released.positive()
            }
            None => {
                self.cache.progress.append = Some(result);
                self.cache.progress.mark(
                    matches!(self.cache.progress.append, Some(Err(_))),
                    Failure::Append,
                );
                if self.cache.progress.first.is_some() {
                    Err(CacheHeldClosedV1)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn crossing_native_once(&mut self, index: usize, compare_transaction: bool) {
        if self.released.is_some() {
            self.released_crossing_native_once(index, compare_transaction);
            return;
        }
        let Some(context) = self.context.as_ref() else {
            self.cache.progress.refuse();
            return;
        };
        let target = context.journal();
        if self.cache.progress.crossing[index].is_some() || self.cache.progress.first.is_some() {
            self.cache.progress.refuse();
            return;
        }
        self.cache.progress.crossing[index] = Some((|| {
            let shape = self
                .cache
                .progress
                .shape
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            shape.writers[1].require(target)?;
            target.require_no_cache_held_history_v1()?;
            if compare_transaction {
                let body = self
                    .cache
                    .progress
                    .body
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(CacheHeldErrorV1::Order)?;
                let prepared = self
                    .cache
                    .progress
                    .transaction
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(CacheHeldErrorV1::Order)?;
                if prepared.as_ref() != self.transaction
                    || body.hold != shape.writers[1].coordinates
                {
                    return Err(CacheHeldErrorV1::Order);
                }
            }
            Ok(())
        })());
        self.cache.progress.mark(
            matches!(self.cache.progress.crossing[index], Some(Err(_))),
            Failure::Crossing,
        );
        let posts =
            audit::observe_bookends(&mut self.cache.originals, self.cache.progress, Some(target));
        self.cache
            .progress
            .mark(posts.failure().is_some(), Failure::Crossing);
        self.cache.progress.crossing_posts[index] = Some(posts);
    }

    fn released_crossing_native_once(&mut self, index: usize, compare_transaction: bool) {
        let Some(context) = self.context.as_ref() else {
            return;
        };
        let Some(released) = self.released.as_deref_mut() else {
            return;
        };
        let target = context.journal();
        if released.crossing[index].is_some() {
            released.refused = true;
            return;
        }
        released.crossing[index] = Some((|| {
            // An actual upper named refusal precedes the old native checks,
            // but it cannot suppress this entered crossing's owed bookends.
            if self.upper_refused {
                return Err(CacheHeldErrorV1::Order);
            }
            let expected = self
                .cache
                .progress
                .after_hold
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(CacheHeldErrorV1::Order)?;
            expected.require(target)?;
            let held = self
                .cache
                .held_receipt_data_v1()
                .map_err(|_| CacheHeldErrorV1::Order)?;
            let lane = released.lane.ok_or(CacheHeldErrorV1::Order)?;
            let key = KeyV1::new(lane, OwnerV1::Cache, 1)?;
            let latest = KeyV1::new(key.lane(), OwnerV1::Cache, 0)?;
            let mut rows = 0_usize;
            for (stored, value) in target.records(aos_sandbox_model::RecordNamespace::CreateStorageHistory) {
                rows += 1;
                if stored == key.encode() && value == held.record {
                    continue;
                }
                if stored == latest.encode() && value == held.latest_head {
                    continue;
                }
                return Err(CacheHeldErrorV1::Order);
            }
            if rows != 2 {
                return Err(CacheHeldErrorV1::Order);
            }
            if compare_transaction {
                let prepared = released
                    .transaction
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .ok_or(CacheHeldErrorV1::Order)?;
                if prepared.as_ref() != self.transaction {
                    return Err(CacheHeldErrorV1::Order);
                }
            }
            Ok(())
        })());
        released.crossing_posts[index] = Some(audit::observe_bookends(
            &mut self.cache.originals,
            self.cache.progress,
            Some(target),
        ));
    }

    fn require_native_positive(&self) -> Result<(), JournalError> {
        if self.upper_refused
            || self.cache.progress.first.is_some()
            || self
                .released
                .as_ref()
                .is_some_and(|released| released.refused || released.failure().is_some())
        {
            Err(JournalError::boundary())
        } else {
            Ok(())
        }
    }

    fn require_stage(&self, expected: Stage) -> Result<(), JournalError> {
        if self.stage == expected && self.context.is_some() {
            Ok(())
        } else {
            Err(JournalError::boundary())
        }
    }

    fn require_gate(&self, gate: &CacheHeldAppendGateV1) -> Result<(), JournalError> {
        if gate.original == self.original {
            Ok(())
        } else {
            Err(JournalError::boundary())
        }
    }

    fn restore_reference(&mut self) {
        if let Some(context) = self.context.take() {
            self.cache.originals.hold = Some(context.into_journal_after_stage_v1());
        }
    }
}

impl Drop for CacheHeldAppendContextV1<'_, '_, '_> {
    fn drop(&mut self) {
        // The lexical guard is scoped inside the caller's shared schedule and
        // drops before this context on unwind. Restore only after stage drop;
        // the original Cache loan remains armed and retains its abort law.
        self.restore_reference();
        if !self.parked {
            match self.released.as_deref_mut() {
                Some(released) => released.refused = true,
                None => self.cache.progress.refuse(),
            }
        }
    }
}

impl<'cache> OriginalCreateStorageCacheLoanV1<'cache> {
    /// Borrows the same Hold under its real admitted Released purpose.
    ///
    /// # Errors
    /// Retains genuine original/purpose refusal and pre-transition native debt.
    /// The opaque owner restores the same reference before any unwind resumes.
    pub fn begin_released_append_once_v1<'append, 'transaction>(
        &'append mut self,
        released: &'append mut released::CacheReleasedOriginalsV1,
        transaction: &'transaction Arc<JournalTransaction>,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) -> Result<
        (
            CacheHeldAppendContextV1<'append, 'cache, 'transaction>,
            CacheHeldAppendGateV1,
        ),
        CacheHeldClosedV1,
    > {
        released.positive()?;
        let prepared = released
            .transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok());
        if released.append.is_some()
            || prepared.is_none_or(|prepared| !Arc::ptr_eq(prepared, transaction))
        {
            released.refused = true;
            return Err(CacheHeldClosedV1);
        }
        released.original = Some((|| {
            self.originals
                .construction
                .require_audit_funding_originals_v1(funding)?;
            funding.require_release_original_v1(self.identity)
        })());
        released.positive()?;
        let hold = self.originals.hold.take().ok_or(CacheHeldClosedV1)?;
        let original = hold as *const Journal as usize;
        let mut context = CacheHeldAppendContextV1 {
            cache: self,
            context: Some(CacheAppendContextV1::new(hold)),
            released: Some(released),
            transaction,
            original,
            settling: None,
            stage: Stage::Entered,
            upper_refused: false,
            coordinates: None,
            durable_bytes: None,
            parked: false,
        };
        let before = match context.context.as_ref() {
            Some(native) => crate::journal::policy::validate_before_create_storage_transition_v1(
                native.journal(),
                transaction,
            ),
            None => Err(JournalError::boundary()),
        };
        match before {
            Ok(settling) => context.settling = settling,
            Err(cause) => {
                let _ = context.retain_result_once_v1(Err(cause));
                return Err(CacheHeldClosedV1);
            }
        }
        Ok((
            context,
            CacheHeldAppendGateV1 {
                original,
                gate: CacheMutationGateV1::Ordinary,
            },
        ))
    }

    /// Borrows the same actual Hold for the finite upper lexical append.
    ///
    /// # Errors
    /// Retains original affinity or original pre-transition semantic refusal.
    /// No upper transition is entered after one of those earlier refusals.
    pub fn begin_held_append_once_v1<'append, 'transaction>(
        &'append mut self,
        transaction: &'transaction Arc<JournalTransaction>,
        funding: &mut ControllerCacheAuditFundingLoanV1<'_, '_>,
    ) -> Result<
        (
            CacheHeldAppendContextV1<'append, 'cache, 'transaction>,
            CacheHeldAppendGateV1,
        ),
        CacheHeldClosedV1,
    > {
        let prepared = self
            .progress
            .transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok());
        if self.progress.first.is_some()
            || self.progress.append.is_some()
            || prepared.is_none_or(|prepared| !Arc::ptr_eq(prepared, transaction))
        {
            self.progress.refuse();
            return Err(CacheHeldClosedV1);
        }
        self.progress.append_original = Some((|| {
            self.originals
                .construction
                .require_audit_funding_originals_v1(funding)?;
            funding.require_initial_held_original_v1(self.identity)
        })());
        self.progress.mark(
            matches!(self.progress.append_original, Some(Err(_))),
            Failure::AppendGeometry,
        );
        if self.progress.first.is_some() {
            return Err(CacheHeldClosedV1);
        }
        let hold = self.originals.hold.take().ok_or(CacheHeldClosedV1)?;
        let original = hold as *const Journal as usize;
        // Construct the restoring owner before entering any fallible native
        // policy body. A caught unwind therefore also restores this exact
        // reference before the upper caller can resume its retained loan.
        let mut context = CacheHeldAppendContextV1 {
            cache: self,
            context: Some(CacheAppendContextV1::new(hold)),
            released: None,
            transaction,
            original,
            settling: None,
            stage: Stage::Entered,
            upper_refused: false,
            coordinates: None,
            durable_bytes: None,
            parked: false,
        };
        let before = match context.context.as_ref() {
            Some(native) => crate::journal::policy::validate_before_create_storage_transition_v1(
                native.journal(),
                transaction,
            ),
            None => Err(JournalError::boundary()),
        };
        match before {
            Ok(settling) => context.settling = settling,
            Err(cause) => {
                let _ = context.retain_result_once_v1(Err(cause));
                return Err(CacheHeldClosedV1);
            }
        }
        Ok((
            context,
            CacheHeldAppendGateV1 {
                original,
                gate: CacheMutationGateV1::Ordinary,
            },
        ))
    }
}
