//! Binds the sole retained semantic driver to the fixed no-history branch.
//!
//! This opaque DATA owner drives an actual supplied indexed canonical cursor.
//! Source and Cache retain their own financial originals, physical files, role
//! selection and independent native posts. Cold completion supplies neither
//! native custody nor a live role. Source-original dependencies keep their
//! existing pending disposition until a real challenge-history owner closes
//! them; this module cannot synthesize that history or a challenge witness.

crate::define_cold_replay_binding_v1!();

#[cfg(target_os = "linux")]
mod native;

pub mod git_prefix;

use aos_sandbox_protocol::domain_ledger::create_storage_history::native_suffix::HistoryPairNativeSuffixV1;
use semantic::SelectedReplayNativeV1 as _;
use aos_sandbox_protocol::domain_ledger::effect_history::{
    CreateStoppedNativeObservationDataV2, CreateStoppedNativeObservationErrorV2,
};

/// Preserves the exact no-history cold semantic result beside its real cursor.
///
/// The invoking role separately admits actual representation before entry and
/// retains the native cursor original and every independently owed post. This
/// DATA owner has no native opener, financial account or role constructor.
///
/// Its default native error preserves existing indexed consumers. The concrete
/// Root and Controller entries retain their own original native errors; the
/// private stage interface cannot be implemented through this public API.
pub struct ColdReplayOriginalV1<E: Error + 'static = CanonicalIndexedReplayErrorV1> {
    original: semantic::SelectedSemanticReplayOriginalV1<E>,
    suffix_failure_selected: bool,
    predecessor_failure_selected: bool,
    stopped_failure_selected: bool,
    delete_preparation_failure_selected: bool,
    git_prefix_failure_selected: bool,
    cache_git_prefix_failure_selected: bool,
    q04_history_failure_selected: bool,
}

impl<E: Error + 'static> ColdReplayOriginalV1<E> {
    /// Creates vacant historical replay destinations without native effects.
    #[must_use]
    pub fn new() -> Self {
        Self {
            original: semantic::SelectedSemanticReplayOriginalV1::new(),
            suffix_failure_selected: false,
            predecessor_failure_selected: false,
            stopped_failure_selected: false,
            delete_preparation_failure_selected: false,
            git_prefix_failure_selected: false,
            cache_git_prefix_failure_selected: false,
            q04_history_failure_selected: false,
        }
    }

    /// Returns the actual inline driver and flag construction planes.
    ///
    /// Family backing is excluded; retained role callers admit it at the real
    /// reached semantic frontier before allocating their family originals.
    #[must_use]
    pub fn receiving_construction_bytes_v1() -> Option<usize> {
        semantic::SelectedSemanticReplayOriginalV1::<E>::receiving_construction_bytes_v1()?
            .checked_add(std::mem::size_of::<Self>()
                .checked_sub(std::mem::size_of::<semantic::SelectedSemanticReplayOriginalV1<E>>())?
                .checked_mul(2)?)?
            .checked_add(std::mem::size_of::<Option<usize>>().checked_mul(2)?)
    }

    /// Returns the same retained driver's compiled byte allowance.
    ///
    /// # Errors
    /// Returns the original checked geometry error on overflow.
    pub fn fixed_demand_v1() -> Result<ResourceVector, JournalError> {
        use aos_sandbox_model::ResourceDimension as D;

        let invalid = || JournalError::LimitExceeded("cold replay owner geometry");
        let driver = semantic::SelectedSemanticReplayOriginalV1::<E>::fixed_demand_v1()?;
        let extra = std::mem::size_of::<Self>()
            .checked_sub(std::mem::size_of::<
                semantic::SelectedSemanticReplayOriginalV1<E>,
            >())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let bytes = driver
            .get(D::MemoryBytes)
            .checked_add(extra)
            .ok_or_else(invalid)?;
        Ok(driver.with(D::MemoryBytes, bytes))
    }
}

impl ColdReplayOriginalV1 {
    /// Compares Mount's fixed catalog at every actual COMMIT and final EOF.
    ///
    /// The existing full semantic recipe and native cursor run unchanged.
    /// Mount separately retains its held writer, financial originals and native
    /// bookends; this finite comparison supplies no native or role authority.
    ///
    /// # Errors
    /// Retains native/semantic failure or selects the comparison's actual cause.
    pub fn observe_indexed_with_mount_git_prefix_once_v1(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        comparison: &mut git_prefix::MountGitPrefixReplayDataV1<'_>,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 {
            cursor,
            observer: ColdObserverV1::MountGitPrefix(comparison),
            captured_end: identity.byte_len(),
            suffix_failure_selected: &mut self.git_prefix_failure_selected,
        };
        // Mount's existing positioned reread is ordinary allocation and
        // disposition, while its genuine upper owner retains native bookends.
        // Keep that same challenge and partial-family policy in the common
        // semantic engine; this DATA observer cannot select a retained grant.
        self.original.observe_ordinary_once(&mut observed, identity, limits, None)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Compares Cache policy/catalog history in the same full ordinary replay.
    ///
    /// The finite observer runs at the existing history hook, matching
    /// the original Cache native-prefix caller. The same Cold(false) recipe,
    /// canonical cursor and full EOF remain mandatory; no callback or native
    /// authority can be supplied through this DATA entrance.
    ///
    /// # Errors
    /// Retains actual semantic/native refusal or selects the observer's exact
    /// first comparison cause without replacing an earlier driver failure.
    pub fn observe_indexed_with_cache_git_prefix_once_v1(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        comparison: &mut git_prefix::CacheGitPrefixReplayDataV1<'_>,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 {
            cursor,
            observer: ColdObserverV1::CacheGitPrefix(comparison),
            captured_end: identity.byte_len(),
            suffix_failure_selected: &mut self.cache_git_prefix_failure_selected,
        };
        self.original.observe_ordinary_once(&mut observed, identity, limits, None)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Returns the actual Cold driver, finite adapter and Cache owner geometry.
    ///
    /// Dynamic canonical frames and semantic models remain separately priced.
    /// # Errors
    /// Preserves checked fixed-layout geometry overflow.
    pub fn fixed_demand_with_cache_git_prefix_v1() -> Result<ResourceVector, JournalError> {
        Self::fixed_demand_with_release_observer_v1()?
            .checked_add(git_prefix::CacheGitPrefixReplayDataV1::fixed_demand_v1()?)
            .map_err(|_| JournalError::LimitExceeded("Cache Git observer geometry"))
    }

    /// Identifies only the actual selected Cache prefix comparison refusal.
    #[must_use]
    pub fn cache_git_prefix_failure_is_selected_v1(&self) -> bool {
        self.cache_git_prefix_failure_selected
    }

    /// Compares the exact Q04 history inside the existing full ordinary Cold recipe.
    ///
    /// The actual history hook precedes compaction/index/semantic mutation.
    /// Complete EOF is recorded only after the full semantic window. The caller
    /// must still finish the same audit with actual post-replay IDs/names and
    /// compare all held native state before any positive role operation.
    ///
    /// # Errors
    /// Retains native/semantic failure or selects the exact comparison cause.
    pub fn observe_indexed_with_q04_native_recipe_once_v1(&mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>, identity: FileIdentity,
        limits: JournalLimits,
        comparison: &mut crate::q04_native_history::Q04NativeRecipeAuditDataV1<'_>,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 { cursor,
            observer: ColdObserverV1::Q04History(comparison), captured_end: identity.byte_len(),
            suffix_failure_selected: &mut self.q04_history_failure_selected };
        self.original.observe_ordinary_once(&mut observed, identity, limits, None)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Prices the actual driver, adapter and fixed Q04 comparison owner.
    ///
    /// # Errors
    /// Refuses checked byte overflow. Actual bank use tracking and dynamic
    /// canonical/semantic models remain separately paid by the native owner.
    pub fn fixed_demand_with_q04_native_recipe_v1() -> Result<ResourceVector, JournalError> {
        Self::fixed_demand_with_release_observer_v1()?
            .checked_add(crate::q04_native_history::Q04NativeRecipeAuditDataV1::fixed_demand_v1()?)
            .map_err(|_| JournalError::LimitExceeded("Q04 Cold observer geometry"))
    }

    /// Identifies only a Q04 comparison actually selected by the Cold hook.
    #[must_use]
    pub fn q04_native_recipe_failure_is_selected_v1(&self) -> bool {
        self.q04_history_failure_selected
    }

    /// Identifies only the actual selected fixed Mount comparison refusal.
    #[must_use]
    pub fn mount_git_prefix_failure_is_selected_v1(&self) -> bool {
        self.git_prefix_failure_selected
    }

    /// Drives the actual supplied indexed cursor through every original hook.
    ///
    /// This uses the fixed no-history branch, including pending original Source
    /// dependencies. Completion does not authenticate the supplied physical
    /// identity, provide a current challenge or authorize a role operation.
    ///
    /// # Errors
    /// Returns a stopping marker on reentry or any native, index, Source, Root,
    /// Delete or capacity refusal; the actual original cause remains borrowed.
    pub fn observe_indexed_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
    ) -> Result<(), ColdReplayClosedV1> {
        self.original
            .observe_native_once(cursor, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Replays actual ordinary DATA with its existing immediate family policy.
    ///
    /// This entry retains no native challenge view and creates no authority.
    /// Its caller owns the actual opening/cursor and preserves the ordinary
    /// current, upper-scratch, pending, index and native disposal frontiers.
    ///
    /// # Errors
    /// Preserves the same typed causes on any semantic or actual cursor/index
    /// refusal. Reentry cannot reset this original or produce a remainder.
    pub fn observe_ordinary_indexed_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
    ) -> Result<(), ColdReplayClosedV1> {
        self.original.observe_ordinary_once(cursor, identity, limits, None)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Returns inline construction and the exact borrowed suffix adapter planes.
    ///
    /// Dynamic model and Source-family backing remain separate real admission.
    #[must_use]
    pub fn receiving_construction_with_release_observer_bytes_v1() -> Option<usize> {
        Self::receiving_construction_bytes_v1()?
            .checked_add(std::mem::size_of::<ObservedCursorV1<'_, '_, '_, '_, '_, '_>>()
                .checked_mul(2)?)
    }

    /// Returns the compiled byte peak including the borrowed suffix adapter.
    ///
    /// Dynamic semantic models, native replay, index backing and the expected
    /// suffix transaction remain separately admitted by the actual receiver.
    ///
    /// # Errors
    /// Returns the original checked geometry error on overflow.
    pub fn fixed_demand_with_release_observer_v1() -> Result<ResourceVector, JournalError> {
        use aos_sandbox_model::ResourceDimension as D;

        let invalid = || JournalError::LimitExceeded("cold release observer geometry");
        let fixed = Self::fixed_demand_v1()?;
        let extra = std::mem::size_of::<ObservedCursorV1<'_, '_, '_, '_, '_, '_>>()
            .checked_mul(2)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let bytes = fixed
            .get(D::MemoryBytes)
            .checked_add(extra)
            .ok_or_else(invalid)?;
        Ok(fixed.with(D::MemoryBytes, bytes))
    }

    /// Compares an optional exact release suffix inside the same full replay.
    ///
    /// Each supplied pair observes the actual COMMIT after all semantic checks
    /// and before its native disposal. Final comparison uses the same admitted
    /// file identity and completed prefix. The caller retains the expected
    /// transaction and progress; successful comparison grants no role authority.
    /// With no observer this immediately uses the existing cold entry.
    ///
    /// # Errors
    /// Returns a stopping marker on reentry, native or semantic refusal, or
    /// suffix mismatch. The supplied progress retains its exact typed cause.
    pub fn observe_indexed_with_release_observer_once(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        suffix: Option<&mut HistoryPairNativeSuffixV1<'_, '_>>,
    ) -> Result<(), ColdReplayClosedV1> {
        let Some(suffix) = suffix else {
            return self.observe_indexed_once(cursor, identity, limits);
        };
        let mut observed = ObservedCursorV1 {
            cursor,
            observer: ColdObserverV1::Release(suffix),
            captured_end: identity.byte_len(),
            suffix_failure_selected: &mut self.suffix_failure_selected,
        };
        self.original
            .observe_native_once(&mut observed, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Prices the same fixed concrete observer adapter used by release replay.
    ///
    /// The predecessor's own inline slots and actual full model/encoding peak
    /// remain separately admitted by its genuine receiving caller.
    ///
    /// # Errors
    /// Preserves the same checked fixed adapter geometry refusal.
    pub fn fixed_demand_with_delete_predecessor_v2() -> Result<ResourceVector, JournalError> {
        Self::fixed_demand_with_release_observer_v1()
    }

    /// Compares the actual pre-Planned Source cut inside the complete cold replay.
    ///
    /// The concrete observer sees the actual borrowed prior-state/BEGIN frontier
    /// before apply and exact final native EOF after all semantic checks. It
    /// supplies comparison DATA only; the role retains files, payment and posts.
    ///
    /// # Errors
    /// Retains the original semantic/native failure or marks the caller-owned
    /// predecessor DATA as the selected typed comparison cause.
    pub fn observe_indexed_with_delete_predecessor_once_v2(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        predecessor: &mut crate::delete_pending::DeleteSourcePredecessorReplayDataV2,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 {
            cursor, observer: ColdObserverV1::Predecessor(predecessor),
            captured_end: identity.byte_len(),
            suffix_failure_selected: &mut self.predecessor_failure_selected,
        };
        self.original.observe_native_once(&mut observed, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Captures the shared graph base from the actual Source BEGIN prior state.
    ///
    /// The caller retains actual C/Source native custody and pays all model planes.
    /// The C map borrow lasts only for this synchronous canonical replay.
    ///
    /// # Errors
    /// Retains canonical replay or exact caller-owned predecessor/graph failure.
    pub fn observe_indexed_with_delete_graph_predecessor_once_v2(
        &mut self, cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity, limits: JournalLimits,
        predecessor: &mut crate::delete_pending::DeleteSourcePredecessorReplayDataV2,
        controller: &std::collections::BTreeMap<
            (aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 {
            cursor, observer: ColdObserverV1::GraphPredecessor { predecessor, controller },
            captured_end: identity.byte_len(),
            suffix_failure_selected: &mut self.predecessor_failure_selected,
        };
        self.original.observe_native_once(&mut observed, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Compares the selected Create transaction within the same complete replay.
    ///
    /// The actual role retains the checked recipe, exact typed refusal, native
    /// cursor and all independent posts. This finite comparison supplies no
    /// native custody or terminal authority. COMMIT observation occurs only
    /// after the ordinary semantic checks and before native disposal; complete
    /// comparison additionally requires the same final semantic/native EOF.
    ///
    /// # Errors
    /// Retains earlier semantic/native failure, or selects the supplied exact
    /// comparison error after a mismatched, repeated or missing transaction.
    pub fn observe_indexed_with_create_stopped_once_v2(
        &mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>,
        identity: FileIdentity,
        limits: JournalLimits,
        observation: &mut CreateStoppedNativeObservationDataV2<'_>,
        failure: &mut Option<CreateStoppedNativeObservationErrorV2>,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 {
            cursor,
            observer: ColdObserverV1::CreateStopped { observation, failure },
            captured_end: identity.byte_len(),
            suffix_failure_selected: &mut self.stopped_failure_selected,
        };
        self.original.observe_native_once(&mut observed, identity, limits)
            .map_err(|_| ColdReplayClosedV1)
    }

    /// Compares accepted Controller COMMIT DATA inside the sole complete replay.
    ///
    /// # Errors
    /// Retains actual native/semantic failure or the selected comparison cause.
    pub fn observe_indexed_with_delete_accepted_once_v3(&mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>, identity: FileIdentity, limits: JournalLimits,
        comparison: &mut crate::delete_pending::DeleteSelectedCommitReplayDataV3,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 { cursor, observer: ColdObserverV1::DeleteAccepted(comparison),
            captured_end: identity.byte_len(), suffix_failure_selected: &mut self.delete_preparation_failure_selected };
        self.original.observe_native_once(&mut observed, identity, limits).map_err(|_| ColdReplayClosedV1)
    }

    /// Compares canonical Batch2 and actual EOF inside the sole complete replay.
    ///
    /// Full Domain Operation/auxiliary semantics remain the Root caller's duty.
    ///
    /// # Errors
    /// Retains actual native/semantic failure or the selected Batch2 comparison cause.
    pub fn observe_indexed_with_delete_current_once_v3(&mut self,
        cursor: &mut CanonicalIndexedReplayV1<'_, '_>, identity: FileIdentity, limits: JournalLimits,
        comparison: &mut crate::delete_pending::SourceDeletePendingReplayDataV1,
    ) -> Result<(), ColdReplayClosedV1> {
        let mut observed = ObservedCursorV1 { cursor, observer: ColdObserverV1::DeleteCurrent(comparison),
            captured_end: identity.byte_len(), suffix_failure_selected: &mut self.delete_preparation_failure_selected };
        self.original.observe_native_once(&mut observed, identity, limits).map_err(|_| ColdReplayClosedV1)
    }

    /// Identifies only the actual selected Delete preparation comparison cause.
    pub fn delete_preparation_failure_is_selected_v3(&self) -> bool { self.delete_preparation_failure_selected }

    /// Identifies only an actual selected strict Create comparison refusal.
    #[must_use]
    pub fn create_stopped_failure_is_selected_v2(&self) -> bool {
        self.stopped_failure_selected
    }

    /// Identifies the retained predecessor model as the selected deeper cause.
    #[must_use]
    pub fn predecessor_failure_is_selected_v2(&self) -> bool {
        self.predecessor_failure_selected
    }

    /// Identifies the caller-owned suffix progress as the selected first cause.
    #[must_use]
    pub fn suffix_failure_is_selected_v1(&self) -> bool {
        self.suffix_failure_selected
    }
}

impl<E: Error + 'static> ColdReplayOriginalV1<E> {
    /// Borrows the exact first native stopping result or semantic cause.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original.failure()
    }

    /// Borrows the same retained Source transition or family diagnostic.
    ///
    /// Selection remains with the real caller's existing first-cause order.
    pub fn source_failure_cause_v1(&self) -> Option<&(dyn Error + 'static)> {
        self.original.source_failure_cause_v1()
    }

    /// Identifies when the real native cursor owns the selected deeper cause.
    #[must_use]
    pub fn native_failure_is_selected_v1(&self) -> bool {
        !self.suffix_failure_selected && !self.predecessor_failure_selected
            && !self.stopped_failure_selected && !self.delete_preparation_failure_selected
            && !self.git_prefix_failure_selected && !self.cache_git_prefix_failure_selected
            && !self.q04_history_failure_selected && self.original.native_failure_is_selected_v1()
    }

    /// Disposes only the reached ordinary prospective map before native current.
    ///
    /// This changes no cause or completion state. Remaining semantic originals
    /// stay resident until the consuming post-current error-disposal window.
    pub fn dispose_ordinary_prospective_v1(&mut self) {
        self.original.dispose_ordinary_prospective_v1();
    }

    /// Moves actual typed ordinary errors while disposing upper semantic scratch.
    ///
    /// The ordinary caller first disposes this prospective map, retires current
    /// parser work, consumes this owner, then retires pending/index/native work.
    /// Retained or selected roles keep this owner through their owed posts and
    /// continue borrowing failure instead. This does not reset or complete it.
    #[must_use]
    pub fn into_ordinary_errors(self) -> (Option<E>, Option<JournalError>) {
        self.original.into_ordinary_errors()
    }

    /// Moves completed comparison DATA once without admitting a protected role.
    pub fn take_remainder_once(&mut self) -> Option<ColdReplayRemainderDataV1> {
        self.original
            .take_remainder_once()
            .map(move_cold_remainder_data_v1)
    }
}

// This concrete comparison adapter cannot select a path, supply authority,
// change parsing, or substitute a caller-defined success callback.
enum ColdObserverV1<'observer, 'expected, 'progress> {
    Q04History(&'observer mut crate::q04_native_history::Q04NativeRecipeAuditDataV1<'expected>),
    CacheGitPrefix(&'observer mut git_prefix::CacheGitPrefixReplayDataV1<'expected>),
    MountGitPrefix(&'observer mut git_prefix::MountGitPrefixReplayDataV1<'expected>),
    DeleteAccepted(&'observer mut crate::delete_pending::DeleteSelectedCommitReplayDataV3),
    DeleteCurrent(&'observer mut crate::delete_pending::SourceDeletePendingReplayDataV1),
    Release(&'observer mut HistoryPairNativeSuffixV1<'expected, 'progress>),
    Predecessor(&'observer mut crate::delete_pending::DeleteSourcePredecessorReplayDataV2),
    GraphPredecessor {
        predecessor: &'observer mut crate::delete_pending::DeleteSourcePredecessorReplayDataV2,
        controller: &'expected std::collections::BTreeMap<
            (aos_sandbox_model::RecordNamespace, Vec<u8>), Vec<u8>>,
    },
    CreateStopped {
        observation: &'observer mut CreateStoppedNativeObservationDataV2<'expected>,
        failure: &'observer mut Option<CreateStoppedNativeObservationErrorV2>,
    },
}

struct ObservedCursorV1<'cursor, 'file, 'index, 'suffix, 'expected, 'progress> {
    cursor: &'cursor mut CanonicalIndexedReplayV1<'file, 'index>,
    observer: ColdObserverV1<'suffix, 'expected, 'progress>,
    captured_end: u64,
    suffix_failure_selected: &'suffix mut bool,
}

impl semantic::SelectedReplayNativeV1 for ObservedCursorV1<'_, '_, '_, '_, '_, '_> {
    type Error = CanonicalIndexedReplayErrorV1;

    fn advance_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.advance_once()
    }

    fn current_commit(
        &self,
    ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalCommitReadViewV1<'_>> {
        self.cursor.current_commit()
    }

    fn validate_compaction_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.validate_compaction_once()
    }

    fn register_and_compare_index_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.register_and_compare_index_once()
    }

    fn observe_history_commit_once(&mut self) -> Result<(), Self::Error> {
        if let ColdObserverV1::Q04History(comparison) = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if comparison.observe_commit_v1(commit).is_err() {
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        if let ColdObserverV1::CacheGitPrefix(comparison) = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if comparison.observe_commit_v1(commit).is_err() {
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        Ok(())
    }

    fn prepare_change_once(&mut self) -> Result<(), Self::Error> {
        if let ColdObserverV1::Predecessor(predecessor) = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if predecessor.observe_commit(commit).is_err() {
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        if let ColdObserverV1::GraphPredecessor { predecessor, controller } = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if predecessor.observe_commit_with_graph_data_v2(commit, controller).is_err() {
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        if let ColdObserverV1::DeleteCurrent(comparison) = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if comparison.observe_commit(commit).is_err() {
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        self.cursor.prepare_change_once()
    }

    fn apply_next_record_once(&mut self) -> Result<bool, Self::Error> {
        self.cursor.apply_next_record_once()
    }

    fn finish_commit_accounting_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.finish_commit_accounting_once()
    }

    fn finish_commit_once(&mut self) -> Result<(), Self::Error> {
        if let ColdObserverV1::MountGitPrefix(comparison) = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if comparison.observe_commit_v1(commit).is_err() {
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        if let ColdObserverV1::Release(suffix) = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
        let (begin_sequence, begin_offset) = commit.begin_position();
        if suffix.observe(
                commit.transaction(),
                begin_sequence,
                commit.commit_sequence(),
                begin_offset,
                commit.coordinates().offset,
            )
            .is_err()
        {
            *self.suffix_failure_selected = true;
            return Err(Self::Error::Closed);
        }
        }
        if let ColdObserverV1::CreateStopped { observation, failure } = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if let Err(cause) = observation.observe_v2(commit.transaction()) {
                **failure = Some(cause);
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        if let ColdObserverV1::DeleteAccepted(comparison) = &mut self.observer {
            let commit = self.cursor.current_commit().ok_or(Self::Error::Closed)?;
            if comparison.observe_commit_v3(&commit).is_err() {
                *self.suffix_failure_selected = true;
                return Err(Self::Error::Closed);
            }
        }
        self.cursor.finish_commit_once()
    }

    fn completed_prefix(
        &self,
    ) -> Option<aos_sandbox_broker::canonical_journal::CanonicalReplayPrefixReadViewV1<'_>> {
        self.cursor.completed_prefix()
    }

    fn finish_semantic_window_once(&mut self) -> Result<(), Self::Error> {
        self.cursor.finish_semantic_window_once()?;
        let prefix = self.cursor.completed_prefix().ok_or(Self::Error::Closed)?;
        let completed = match &mut self.observer {
            ColdObserverV1::Q04History(comparison) => comparison.observe_prefix_v1(
                prefix, self.captured_end,
            ).map_err(|_| Self::Error::Closed),
            ColdObserverV1::CacheGitPrefix(comparison) => comparison.finish_prefix_v1(
                prefix, self.captured_end,
            ).map_err(|_| Self::Error::Closed),
            ColdObserverV1::MountGitPrefix(comparison) => comparison.finish_prefix_v1(
                prefix, self.captured_end,
            ).map_err(|_| Self::Error::Closed),
            ColdObserverV1::DeleteAccepted(comparison) => comparison.finish_prefix_v3(prefix, self.captured_end)
                .map_err(|_| Self::Error::Closed),
            ColdObserverV1::DeleteCurrent(comparison) => comparison.finish_prefix(prefix, self.captured_end)
                .map_err(|_| Self::Error::Closed),
            ColdObserverV1::Release(suffix) => {
                let coordinates = prefix.coordinates();
                suffix.finish(coordinates.durable_next_sequence, coordinates.durable_end,
                    self.captured_end).map_err(|_| Self::Error::Closed)
            }
            ColdObserverV1::Predecessor(predecessor)
                | ColdObserverV1::GraphPredecessor { predecessor, .. } => predecessor.finish_prefix(prefix,
                self.captured_end).map_err(|_| Self::Error::Closed),
            ColdObserverV1::CreateStopped { observation, failure } => {
                observation.require_observed_v2().map_err(|cause| {
                    **failure = Some(cause);
                    Self::Error::Closed
                })
            },
        };
        if completed.is_err() {
            *self.suffix_failure_selected = true;
            return Err(Self::Error::Closed);
        }
        Ok(())
    }
}

impl<E: Error + 'static> Default for ColdReplayOriginalV1<E> {
    fn default() -> Self {
        Self::new()
    }
}

/// Contains the same completed historical remainder without native authority.
pub struct ColdReplayRemainderDataV1 {
    /// Exact observed committed challenge rows, with no physical-history claim.
    pub challenge_history: Vec<crate::replay::challenge::SourceOriginalChallengeCheckpointV5>,
    /// Actual no-history replay state; dependencies can still require closure.
    pub original_replay: SourceOriginalReplayDataV5<()>,
    /// Records the original compaction disposition.
    pub history_compacted: bool,
    /// Retains the deny-only lower Q04 history provenance bit.
    pub q04_lower_history_present: bool,
}

/// Stops a cold DATA driver while the real cursor and model owners retain cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("cold semantic replay is closed")]
pub struct ColdReplayClosedV1;

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use aos_sandbox_broker::canonical_journal::{
        CanonicalReplayOriginalV1, coordinator::indexed_replay::CanonicalReplayIndexOriginalsV1,
    };
    use aos_sandbox_protocol::domain_ledger::transaction::encode_transaction;

    fn committed_file(namespace: RecordNamespace) -> std::fs::File {
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                namespace,
                b"fixture".to_vec(),
                b"not-a-capacity-family".to_vec(),
            )],
        )
        .unwrap();
        let mut file = tempfile::tempfile().unwrap();
        for frame in encode_transaction(&transaction, 1).unwrap() {
            file.write_all(&frame).unwrap();
        }
        file
    }

    fn expected_pair() -> JournalTransaction {
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RECORD_OVERHEAD_BYTES, RecordCoordinatesV1,
            RecordEnvelopeV1, native_suffix::history_pair_transaction_id_v1,
        };

        let key = KeyV1::new([7; 16], OwnerV1::Source, 1).unwrap();
        let mut body = vec![0; RECORD_OVERHEAD_BYTES];
        let checksum = RecordEnvelopeV1::encode_into(
            RecordCoordinatesV1 {
                key,
                phase: PhaseV1::new(OwnerV1::Source, 1).unwrap(),
                predecessor: [0; 32],
                correlation: [8; 32],
            },
            &[],
            &mut body,
        )
        .unwrap();
        let head_key = KeyV1::new([7; 16], OwnerV1::Source, 0).unwrap();
        JournalTransaction::new(
            history_pair_transaction_id_v1(OwnerV1::Source, checksum),
            vec![
                JournalRecord::put(
                    RecordNamespace::CreateStorageHistory,
                    key.encode().to_vec(),
                    body,
                ),
                JournalRecord::put(
                    RecordNamespace::CreateStorageHistory,
                    head_key.encode().to_vec(),
                    LatestHeadV1::new(1, checksum).unwrap().encode().to_vec(),
                ),
            ],
        )
        .unwrap()
    }

    fn orphaned_provisioning_file(compaction: bool) -> std::fs::File {
        use aos_sandbox_model::{
            AssignmentEpoch, ObjectDigest, OperationId, ProjectId, ResourceId,
            Revision, SandboxId,
        };
        use aos_sandbox_protocol::domain_ledger::provisioning_resources::{
            ProvisioningModeDataV1, ProvisioningResourceFieldsV1,
            ProvisioningResourceRecordsV1,
        };

        let records = ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
            mode: ProvisioningModeDataV1::CreateStopped,
            parent: OperationId::from_bytes([1; 16]),
            publication_operation: OperationId::from_bytes([2; 16]),
            sandbox: SandboxId::from_bytes([3; 16]),
            project: ProjectId::from_bytes([4; 16]),
            assignment: ResourceId::from_bytes([5; 16]),
            reservation: ResourceId::from_bytes([6; 16]),
            epoch: AssignmentEpoch::new(1),
            reservation_revision: Revision::new(1),
            public_request: ObjectDigest::from_bytes([7; 32]),
            manifest: ObjectDigest::from_bytes([8; 32]),
            source_draft: ObjectDigest::from_bytes([9; 32]),
            root_plan: ObjectDigest::from_bytes([10; 32]),
            child_head: ObjectDigest::from_bytes([11; 32]),
            inclusive_grant: ObjectDigest::from_bytes([12; 32]),
        }).unwrap();
        let mut id = [13; 16];
        if compaction {
            // The canonical writer numbers its first compacted chunk from one.
            id[..8].copy_from_slice(&1_u64.to_le_bytes());
            id[8..].copy_from_slice(b"compact1");
        }
        let transaction = JournalTransaction::new(id, records.records_v1().to_vec()).unwrap();
        let mut file = tempfile::tempfile().unwrap();
        for frame in encode_transaction(&transaction, 1).unwrap() {
            file.write_all(&frame).unwrap();
        }
        file
    }

    #[test]
    fn orphaned_provisioning_commit_retains_actual_map_and_cause_before_disposal() {
        use aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1;

        let file = orphaned_provisioning_file(false);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native.begin_semantic_cursor_once(&file, limits, identity.byte_len()).unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut index, &mut index_original,
        );
        let mut cold = ColdReplayOriginalV1::new();

        assert!(cold.observe_indexed_once(&mut indexed, identity, limits).is_err());

        assert!(matches!(cold.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::ProvisioningResources(ProvisioningResourceLinkErrorV1::Mismatch))));
        assert!(!cold.native_failure_is_selected_v1());
        assert_eq!(indexed.current_commit().unwrap().prior_state().len(), 3);
        assert!(indexed.completed_prefix().is_none());
        assert!(cold.take_remainder_once().is_none());
        let first = cold.failure().unwrap() as *const (dyn Error + 'static);

        assert!(cold.observe_indexed_once(&mut indexed, identity, limits).is_err());

        assert!(std::ptr::addr_eq(first, cold.failure().unwrap() as *const (dyn Error + 'static)));
        assert!(indexed.current_commit().is_some());
    }

    #[test]
    fn ordinary_orphaned_commit_moves_its_typed_cause_between_native_disposals() {
        use aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1;

        let file = orphaned_provisioning_file(false);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native.begin_ordinary_semantic_cursor_once(
            &file, limits, identity.byte_len(),
        ).unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut index, &mut index_original,
        );
        let mut cold = ColdReplayOriginalV1::new();

        assert!(cold.observe_ordinary_indexed_once(&mut indexed, identity, limits).is_err());
        let cause_text = cold.failure().unwrap().to_string();
        assert_eq!(indexed.current_commit().unwrap().prior_state().len(), 3);
        assert!(cold.take_remainder_once().is_none());
        drop(indexed);

        cold.dispose_ordinary_prospective_v1();
        assert!(native.dispose_ordinary_current_once());
        let (native_error, semantic_error) = cold.into_ordinary_errors();
        assert!(native_error.is_none());
        let semantic_error = semantic_error.unwrap();
        assert_eq!(semantic_error.to_string(), cause_text);
        assert!(matches!(semantic_error, JournalError::ProvisioningResources(
            ProvisioningResourceLinkErrorV1::Mismatch
        )));
        assert!(native.dispose_ordinary_pending_once());
        assert!(index_original.into_ordinary_error().is_none());
        drop(index);
        assert!(native.into_ordinary_error().is_none());
    }

    #[test]
    fn orphaned_provisioning_compaction_is_refused_at_complete_prefix() {
        use aos_sandbox_protocol::domain_ledger::provisioning_resources::ProvisioningResourceLinkErrorV1;

        let file = orphaned_provisioning_file(true);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native.begin_semantic_cursor_once(&file, limits, identity.byte_len()).unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut index, &mut index_original,
        );
        let mut cold = ColdReplayOriginalV1::new();

        assert!(cold.observe_indexed_once(&mut indexed, identity, limits).is_err());

        assert!(matches!(cold.failure().unwrap().downcast_ref::<JournalError>(),
            Some(JournalError::ProvisioningResources(ProvisioningResourceLinkErrorV1::Mismatch))));
        assert_eq!(indexed.completed_prefix().unwrap().state().len(), 3);
        assert!(cold.take_remainder_once().is_none());
    }

    #[test]
    fn release_mismatch_keeps_actual_commit_and_typed_cause_before_disposal() {
        use aos_sandbox_protocol::domain_ledger::{
            create_storage_history::native_suffix::{
                HistoryPairNativeSuffixProgressV1, HistoryPairSuffixErrorV1,
            },
            transaction::encoded_transaction_append_bytes,
        };

        let file = committed_file(RecordNamespace::Operation);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let expected = expected_pair();
        let end = encoded_transaction_append_bytes(&expected).unwrap();
        let mut progress = HistoryPairNativeSuffixProgressV1::new();
        let mut suffix =
            HistoryPairNativeSuffixV1::new(&expected, &mut progress, 1, 0, 5, end).unwrap();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native
            .begin_semantic_cursor_once(&file, limits, identity.byte_len())
            .unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut index,
            &mut index_original,
        );
        let mut cold = ColdReplayOriginalV1::new();

        assert!(
            cold.observe_indexed_with_release_observer_once(
                &mut indexed,
                identity,
                limits,
                Some(&mut suffix)
            )
            .is_err()
        );

        assert!(cold.suffix_failure_is_selected_v1());
        assert!(!cold.native_failure_is_selected_v1());
        assert_eq!(
            suffix.failure(),
            Some(&HistoryPairSuffixErrorV1::Transaction)
        );
        assert!(indexed.current_commit().is_some());
        assert!(indexed.completed_prefix().is_none());
        let first = cold.failure().unwrap() as *const (dyn Error + 'static);
        assert!(
            cold.observe_indexed_with_release_observer_once(
                &mut indexed,
                identity,
                limits,
                Some(&mut suffix)
            )
            .is_err()
        );
        assert!(std::ptr::addr_eq(
            first,
            cold.failure().unwrap() as *const (dyn Error + 'static)
        ));
        assert_eq!(
            suffix.failure(),
            Some(&HistoryPairSuffixErrorV1::Transaction)
        );
        assert!(cold.take_remainder_once().is_none());
    }

    #[test]
    fn earlier_semantic_failure_does_not_enter_the_release_observer() {
        use aos_sandbox_protocol::domain_ledger::{
            create_storage_history::native_suffix::HistoryPairNativeSuffixProgressV1,
            transaction::encoded_transaction_append_bytes,
        };

        let file = committed_file(RecordNamespace::GlobalCapacityReservation);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let expected = expected_pair();
        let end = encoded_transaction_append_bytes(&expected).unwrap();
        let mut progress = HistoryPairNativeSuffixProgressV1::new();
        let mut suffix =
            HistoryPairNativeSuffixV1::new(&expected, &mut progress, 1, 0, 5, end).unwrap();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native
            .begin_semantic_cursor_once(&file, limits, identity.byte_len())
            .unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut index,
            &mut index_original,
        );
        let mut cold = ColdReplayOriginalV1::new();

        assert!(
            cold.observe_indexed_with_release_observer_once(
                &mut indexed,
                identity,
                limits,
                Some(&mut suffix)
            )
            .is_err()
        );

        assert!(!cold.suffix_failure_is_selected_v1());
        assert!(suffix.failure().is_none());
        assert!(indexed.current_commit().is_some());
        let first = cold.failure().unwrap() as *const (dyn Error + 'static);
        assert!(
            cold.observe_indexed_with_release_observer_once(&mut indexed, identity, limits, None)
                .is_err()
        );
        assert!(std::ptr::addr_eq(
            first,
            cold.failure().unwrap() as *const (dyn Error + 'static)
        ));
    }

    #[test]
    fn unrelated_commit_keeps_the_existing_cold_semantic_disposition() {
        let file = committed_file(RecordNamespace::Operation);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native
            .begin_semantic_cursor_once(&file, limits, file.metadata().unwrap().len())
            .unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut index,
            &mut index_original,
        );
        let mut cold = ColdReplayOriginalV1::new();

        cold.observe_indexed_once(&mut indexed, identity, limits)
            .unwrap();

        assert!(cold.failure().is_none());
        assert!(indexed.completed_prefix().is_some());
        let remainder = cold.take_remainder_once().unwrap();
        assert!(!remainder.original_replay.needs_closure());
        assert!(!remainder.q04_lower_history_present);
        assert!(cold.take_remainder_once().is_none());
    }

    #[test]
    fn foreign_capacity_commit_is_checked_before_native_disposal() {
        let file = committed_file(RecordNamespace::GlobalCapacityReservation);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native
            .begin_semantic_cursor_once(&file, limits, file.metadata().unwrap().len())
            .unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor,
            &mut index,
            &mut index_original,
        );
        let mut cold = ColdReplayOriginalV1::new();

        assert!(
            cold.observe_indexed_once(&mut indexed, identity, limits)
                .is_err()
        );

        let first = cold.failure().unwrap() as *const (dyn Error + 'static);
        assert!(!cold.native_failure_is_selected_v1());
        assert!(indexed.current_commit().is_some());
        assert!(indexed.completed_prefix().is_none());
        assert!(cold.take_remainder_once().is_none());
        assert!(
            cold.observe_indexed_once(&mut indexed, identity, limits)
                .is_err()
        );
        assert!(std::ptr::addr_eq(
            first,
            cold.failure().unwrap() as *const (dyn Error + 'static)
        ));
    }
    #[test]
    fn earlier_semantic_failure_cannot_materialize_a_graph_predecessor() {
        let file = committed_file(RecordNamespace::GlobalCapacityReservation);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native.begin_semantic_cursor_once(&file, limits, identity.byte_len()).unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut index, &mut index_original);
        let query = aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1 {
            nonce: [1; 16], project: [2; 16], operation: [3; 16], batch: [4; 32],
            boot: [5; 16], started: 100, cutoff: 1_000,
        };
        let mut predecessor = crate::delete_pending::DeleteSourcePredecessorReplayDataV2::
            with_graph_census_data_v2(query, [6; 64], Vec::new());
        let mut cold = ColdReplayOriginalV1::new();
        let controller = BTreeMap::new();

        assert!(cold.observe_indexed_with_delete_graph_predecessor_once_v2(
            &mut indexed, identity, limits, &mut predecessor, &controller).is_err());
        assert!(!cold.predecessor_failure_is_selected_v2());
        assert!(predecessor.failure().is_none());
        assert!(predecessor.take_graph_base_data_v2().is_err());
        assert!(indexed.current_commit().is_some());
        assert!(indexed.completed_prefix().is_none());
        assert!(cold.take_remainder_once().is_none());
        let first = cold.failure().unwrap() as *const (dyn Error + 'static);

        assert!(cold.observe_indexed_with_delete_graph_predecessor_once_v2(
            &mut indexed, identity, limits, &mut predecessor, &controller).is_err());
        assert!(std::ptr::addr_eq(first, cold.failure().unwrap() as *const (dyn Error + 'static)));
        assert!(predecessor.take_graph_base_data_v2().is_err());
    }

    #[test]
    fn earlier_semantic_failure_does_not_enter_source_predecessor_or_replace_cause() {
        let file = committed_file(RecordNamespace::GlobalCapacityReservation);
        let identity = FileIdentity::of::<JournalError>(&file).unwrap();
        let limits = JournalLimits::default();
        let mut native = CanonicalReplayOriginalV1::new();
        let mut index = BTreeMap::new();
        let mut index_original = CanonicalReplayIndexOriginalsV1::new();
        let cursor = native.begin_semantic_cursor_once(&file, limits, identity.byte_len()).unwrap();
        let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
            cursor, &mut index, &mut index_original);
        let query = aos_sandbox_protocol::domain_ledger::delete_root::source_current::SourceDeleteCurrentQueryDataV1 {
            nonce: [1; 16], project: [2; 16], operation: [3; 16], batch: [4; 32],
            boot: [5; 16], started: 100, cutoff: 1_000,
        };
        let mut predecessor = crate::delete_pending::DeleteSourcePredecessorReplayDataV2::new(query, [6; 64]);
        let mut cold = ColdReplayOriginalV1::new();

        assert!(cold.observe_indexed_with_delete_predecessor_once_v2(
            &mut indexed, identity, limits, &mut predecessor).is_err());

        assert!(!cold.predecessor_failure_is_selected_v2());
        assert!(predecessor.failure().is_none());
        assert!(predecessor.data_v2().is_err());
        assert!(indexed.current_commit().is_some());
        assert!(indexed.completed_prefix().is_none());
        assert!(cold.take_remainder_once().is_none());
        let first = cold.failure().unwrap() as *const (dyn Error + 'static);

        assert!(cold.observe_indexed_with_delete_predecessor_once_v2(
            &mut indexed, identity, limits, &mut predecessor).is_err());
        assert!(std::ptr::addr_eq(first, cold.failure().unwrap() as *const (dyn Error + 'static)));
        assert!(predecessor.failure().is_none());
    }

}
