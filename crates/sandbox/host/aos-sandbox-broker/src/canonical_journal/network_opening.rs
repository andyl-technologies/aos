//! Holds image-fixed Network journal originals without role semantic authority.
//!
//! The actual Network or Session receiver prepays fixed native custody, then
//! the same captured prefix before replay. It drives the existing indexed
//! cursor at semantic frontiers and retains its own comparison results. No
//! path, UID, file, payer or successful role marker can replace these originals.

use std::error::Error;
use std::path::Path;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::recovery::RecoveryTailMode;
use super::coordinator::indexed_replay::CanonicalIndexedReplayV1;
use super::{
    CanonicalJournalInstanceDataV1, CanonicalOrdinaryHeldJournalV1,
    CanonicalOrdinaryOpeningOriginalsV1, CanonicalReplayExtentDataV1,
    CanonicalWriterOpeningOriginalsV1, JournalLimits, NativeJournalDataErrorV1 as Cause,
    RecoveryReport,
};
use crate::writer_currentness::WriterCurrentnessOriginalsV1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Recipe {
    Session,
    Creation,
    Lifecycle,
    Preparation,
    Namespace,
    Worker,
}

impl Recipe {
    const fn directory(self) -> &'static str {
        match self {
            Self::Session => "/var/lib/aos/sandbox-network/broker-session",
            Self::Worker => "/var/lib/aos-sandbox-network-worker",
            _ => "/var/lib/aos/sandbox-network/broker-state",
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Session => "session.journal",
            Self::Creation => "network-state.journal",
            Self::Lifecycle => "network-lifecycle-state.journal",
            Self::Preparation => "network-preparations.journal",
            Self::Namespace => "network-namespaces.journal",
            Self::Worker => "network-worker-replay.journal",
        }
    }
}

/// Retains one fixed Network recipe and every reached native/replay partial.
///
/// Its named constructors select existing image paths only. A completed native
/// transfer supplies neither Network MAC validation nor Session admission.
pub struct NetworkCapturedJournalOpeningOriginalV1 {
    recipe: Recipe,
    original: CanonicalOrdinaryOpeningOriginalsV1,
    limits: Option<JournalLimits>,
    allow_create: bool,
    extent: Option<Result<CanonicalReplayExtentDataV1, Cause>>,
    before: WriterCurrentnessOriginalsV1<Cause>,
    after: WriterCurrentnessOriginalsV1<Cause>,
    before_result: Option<Result<(), Cause>>,
    after_result: Option<Result<(), Cause>>,
    final_names: [WriterCurrentnessOriginalsV1<Cause>; 2],
    final_results: [Option<Result<(), Cause>>; 2],
    entered: bool,
    taken: bool,
    closed: Option<Cause>,
}

impl NetworkCapturedJournalOpeningOriginalV1 {
    const fn new(recipe: Recipe) -> Self {
        Self {
            recipe,
            original: CanonicalOrdinaryOpeningOriginalsV1::new(),
            limits: None,
            allow_create: false,
            extent: None,
            before: WriterCurrentnessOriginalsV1::new(),
            after: WriterCurrentnessOriginalsV1::new(),
            before_result: None,
            after_result: None,
            final_names: [
                WriterCurrentnessOriginalsV1::new(),
                WriterCurrentnessOriginalsV1::new(),
            ],
            final_results: [None, None],
            entered: false,
            taken: false,
            closed: None,
        }
    }

    /// Creates empty fixed Session custody without opening or admitting a role.
    #[must_use]
    const fn session() -> Self {
        Self::new(Recipe::Session)
    }

    /// Creates empty fixed creation-catalog custody.
    #[must_use]
    pub const fn creation() -> Self {
        Self::new(Recipe::Creation)
    }

    /// Creates empty fixed lifecycle-catalog custody.
    #[must_use]
    pub const fn lifecycle() -> Self {
        Self::new(Recipe::Lifecycle)
    }

    /// Creates empty fixed preparation-catalog custody.
    #[must_use]
    pub const fn preparation() -> Self {
        Self::new(Recipe::Preparation)
    }

    /// Creates empty fixed namespace-catalog custody.
    #[must_use]
    pub const fn namespace() -> Self {
        Self::new(Recipe::Namespace)
    }

    /// Creates empty fixed Prepare-worker replay custody.
    #[must_use]
    pub const fn worker() -> Self {
        Self::new(Recipe::Worker)
    }

    /// Prices this actual native owner before fixed preparation or allocation.
    ///
    /// # Errors
    /// Preserves the fixed native supplier or checked geometry failure.
    pub fn fixed_preparation_demand(&self) -> Result<ResourceVector, Cause> {
        Self::fixed_demand(self.recipe)
    }

    fn fixed_demand(recipe: Recipe) -> Result<ResourceVector, Cause> {
        let fixed = CanonicalWriterOpeningOriginalsV1::additional_fixed_receiving_demand_v1(
            Path::new(recipe.directory()),
            recipe.name(),
        )?;
        let one = WriterCurrentnessOriginalsV1::<Cause>::fixed_demand_v1(
            Path::new(recipe.directory()),
            recipe.name(),
        )?;
        // The common recipe replaces, rather than duplicates, the opening
        // headers inside both outer planes. The original unit allocation is
        // still prepaid here, before capture or native acquisition.
        let bytes = std::mem::size_of::<Self>()
            .checked_sub(std::mem::size_of::<CanonicalOrdinaryOpeningOriginalsV1>())
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(|bytes| {
                bytes.checked_add(
                    CanonicalOrdinaryOpeningOriginalsV1::receiving_construction_bytes_v1::<()>()?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(CanonicalJournalInstanceDataV1::allocation_receiving_bytes_v1()?)
            })
            .ok_or(Cause::JournalTooLarge)?;
        let bytes = u64::try_from(bytes).map_err(|_| Cause::JournalTooLarge)?;
        // A failed before and its independently owed after can coexist. Final
        // checks are entered only after both positive samples have physically
        // retired; each final named/directory sample retires before the next.
        // Therefore that same two-sample peak dominates the final frontier.
        fixed
            .checked_add(one)
            .and_then(|demand| demand.checked_add(one))
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes)))
            .map_err(|_| Cause::JournalTooLarge)
    }

    /// Prices fixed native creation custody without constructing an owner.
    ///
    /// # Errors
    /// Preserves the same checked native geometry failure before allocation.
    pub fn creation_receiving_demand_v1() -> Result<ResourceVector, Cause> {
        Self::fixed_demand(Recipe::Creation)
    }

    /// Prices fixed native lifecycle custody without constructing an owner.
    ///
    /// # Errors
    /// Preserves the same checked native geometry failure before allocation.
    pub fn lifecycle_receiving_demand_v1() -> Result<ResourceVector, Cause> {
        Self::fixed_demand(Recipe::Lifecycle)
    }

    /// Prices fixed native preparation custody without constructing an owner.
    ///
    /// # Errors
    /// Preserves the same checked native geometry failure before allocation.
    pub fn preparation_receiving_demand_v1() -> Result<ResourceVector, Cause> {
        Self::fixed_demand(Recipe::Preparation)
    }

    /// Prices fixed native namespace custody without constructing an owner.
    ///
    /// # Errors
    /// Preserves the same checked native geometry failure before allocation.
    pub fn namespace_receiving_demand_v1() -> Result<ResourceVector, Cause> {
        Self::fixed_demand(Recipe::Namespace)
    }

    /// Prices fixed native worker custody without constructing an owner.
    ///
    /// # Errors
    /// Preserves the same checked native geometry failure before allocation.
    pub fn worker_receiving_demand_v1() -> Result<ResourceVector, Cause> {
        Self::fixed_demand(Recipe::Worker)
    }

    /// Captures only this fixed recipe once after actual native admission.
    pub fn prepare_once(&mut self, limits: JournalLimits, allow_create: bool) {
        if self.limits.is_some() || self.closed.is_some() || self.taken {
            self.closed.get_or_insert(Cause::ProtectedBoundary);
            return;
        }
        if self.original.capture_instance_once_v1().is_err() {
            self.closed.get_or_insert(Cause::ProtectedBoundary);
            return;
        }
        self.limits = Some(limits);
        self.allow_create = allow_create;
        if self
            .original
            .prepare_retaining_once_v1(
                Path::new(self.recipe.directory()),
                self.recipe.name(),
                limits,
                0,
                allow_create,
            )
            .is_ok()
        {
            self.extent = Some(self.original.prepared_extent_v1());
        }
    }

    /// Borrows the actual held-prefix geometry before replay entry.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&CanonicalReplayExtentDataV1> {
        if self.entered || self.taken || self.closed.is_some() {
            return None;
        }
        self.extent.as_ref()?.as_ref().ok()
    }

    /// Begins the same indexed cursor after the role paid its actual extent.
    ///
    /// # Errors
    /// Retains the original name/identity/cursor failure and rejects reentry.
    /// The caller still owes [`Self::observe_after_owed_once`] on every return.
    pub fn begin_replay_once(
        &mut self,
    ) -> Result<
        (
            aos_sandbox_journal::protected_storage::FileIdentity,
            CanonicalIndexedReplayV1<'_, '_>,
        ),
        Cause,
    > {
        if self.entered
            || self.taken
            || self.closed.is_some()
            || !matches!(self.extent, Some(Ok(_)))
        {
            self.closed.get_or_insert(Cause::ProtectedBoundary);
            return Err(Cause::ProtectedBoundary);
        }
        self.entered = true;
        self.before_result = Some(self.original.observe_names_retaining_v1(
            Path::new(self.recipe.directory()),
            self.recipe.name(),
            0,
            &mut self.before,
        ));
        self.before.settle_positive_once_v1();
        if !matches!(self.before_result, Some(Ok(()))) {
            return Err(Cause::ProtectedBoundary);
        }
        let identity = self.original.prepare_parser_identity_once_v1()?;
        let cursor = self.original.begin_indexed_replay_once_v1()?;
        Ok((identity, cursor))
    }

    /// Copies this original's retained parser identity for full role semantics.
    #[must_use]
    pub fn parser_identity_data_v1(
        &self,
    ) -> Option<aos_sandbox_journal::protected_storage::FileIdentity> {
        self.original.parser_identity_data_v1()
    }

    /// Finishes the same native tail only after the caller's semantic success.
    ///
    /// # Errors
    /// Retains native tail/truncate/sync refusal. This is not role completion.
    pub fn finish_tail_once(&mut self) -> Result<(), Cause> {
        if !self.original.indexed_replay_complete_data_v1() {
            return Err(Cause::ProtectedBoundary);
        }
        self.original
            .finish_replayed_tail_once_v1(if self.allow_create {
                RecoveryTailMode::RepairIncomplete
            } else {
                RecoveryTailMode::RejectIncomplete
            })
    }

    /// Runs the already-owed independent native after even after body refusal.
    pub fn observe_after_owed_once(&mut self) {
        if !self.entered || self.after_result.is_some() {
            self.closed.get_or_insert(Cause::ProtectedBoundary);
            return;
        }
        self.after_result = Some(self.original.observe_names_retaining_v1(
            Path::new(self.recipe.directory()),
            self.recipe.name(),
            0,
            &mut self.after,
        ));
        self.after.settle_positive_once_v1();
    }

    // Final names stay at the same fixed-recipe frontier. The common owner
    // parks its actual completed bundle before native traversal retirement;
    // any retirement refusal keeps the whole native/index partial there.
    fn prepare_held_transfer_once_v1(&mut self) -> Option<()> {
        if self.taken
            || self.failure().is_some()
            || !self.original.indexed_replay_complete_data_v1()
            || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
        {
            return None;
        }
        for slot in 0..2 {
            if self.final_results[slot].is_some() {
                return None;
            }
            self.final_results[slot] = Some(if slot == 0 {
                self.original.observe_names_retaining_v1(
                    Path::new(self.recipe.directory()),
                    self.recipe.name(),
                    0,
                    &mut self.final_names[slot],
                )
            } else {
                self.original.observe_directory_retaining_v1(
                    Path::new(self.recipe.directory()),
                    0,
                    &mut self.final_names[slot],
                )
            });
            if !matches!(self.final_results[slot], Some(Ok(()))) {
                return None;
            }
            self.final_names[slot].settle_positive_once_v1();
        }
        self.original.prepare_completed_transfer_once_v1().ok()?;
        self.original.retire_completed_traversal_once_v1().ok()?;
        Some(())
    }

    /// Transfers this completed fixed capture as the same actual held owner.
    ///
    /// Final name/directory checks and traversal retirement precede transfer.
    /// The opening keeps its original comparison allocation through later posts.
    #[must_use]
    pub fn take_held_once_v1<P>(
        &mut self,
        selection: P,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P>, RecoveryReport)> {
        self.prepare_held_transfer_once_v1()?;
        let result = self
            .original
            .take_held_with_captured_instance_once_v1(selection)?;
        self.taken = true;
        Some(result)
    }

    fn take_prepared_held_with_independent_late_payload_once_v1<P, I>(
        &mut self,
        selection: P,
        payload: I,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)> {
        if self.taken
            || self.failure().is_some()
            || !self.original.indexed_replay_complete_data_v1()
            || !matches!(self.before_result, Some(Ok(())))
            || !matches!(self.after_result, Some(Ok(())))
            || !self
                .final_results
                .iter()
                .all(|result| matches!(result, Some(Ok(()))))
        {
            return None;
        }
        let result = self
            .original
            .take_held_with_independent_late_payload_once_v1(selection, payload)?;
        self.taken = true;
        Some(result)
    }

    /// Borrows this actual capture's private allocation for comparison only.
    ///
    /// Cloning the existing Arc allocates nothing and creates no native owner.
    #[must_use]
    pub fn capture_identity_data_v1(&self) -> Option<CanonicalJournalInstanceDataV1> {
        self.original.captured_instance_data_v1().cloned()
    }

    /// Compares the same capture allocation without supplying readiness.
    #[must_use]
    pub fn same_capture_data_v1(&self, identity: &CanonicalJournalInstanceDataV1) -> bool {
        self.original
            .captured_instance_data_v1()
            .is_some_and(|held| held.same_original_v1(identity))
    }

    /// Compares only the actual original transfer's intrinsic allocation.
    #[must_use]
    pub fn matches_writer_data_v1(&self, identity: &CanonicalJournalInstanceDataV1) -> bool {
        self.taken && self.same_capture_data_v1(identity)
    }

    /// Borrows fixed append-name DATA without granting a native or role owner.
    #[must_use]
    pub fn append_binding_data_v1(&self) -> (&'static str, &'static str, u32) {
        (self.recipe.directory(), self.recipe.name(), 0)
    }

    /// Borrows the same actual first retained native/index or name cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .native_failure_v1()
            .or_else(|| self.extent.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.original.index_failure_v1())
            .or_else(|| self.before.failure())
            .or_else(|| {
                self.before_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.after.failure())
            .or_else(|| {
                self.after_result
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.final_names
                    .iter()
                    .find_map(WriterCurrentnessOriginalsV1::failure)
            })
            .or_else(|| {
                self.final_results
                    .iter()
                    .find_map(|result| result.as_ref()?.as_ref().err().map(|cause| cause as _))
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

/// Owns only the fixed Network Session acquisition lent by its real service.
///
/// Other Network catalogs cannot substitute their similarly shaped native
/// capture at this typed Session boundary. Semantic replay remains in the
/// actual Domain Session receiver, under the same service opening loan.
///
/// A catalog capture cannot be substituted for this fixed Session original:
///
/// ```compile_fail
/// use aos_sandbox_broker::canonical_journal::network_opening::{
///     NetworkBrokerSessionCapturedJournalOpenV4, NetworkCapturedJournalOpeningOriginalV1,
/// };
/// fn session_only(_: &mut NetworkBrokerSessionCapturedJournalOpenV4) {}
/// let mut catalog = NetworkCapturedJournalOpeningOriginalV1::creation();
/// session_only(&mut catalog);
/// ```
pub struct NetworkBrokerSessionCapturedJournalOpenV4(NetworkCapturedJournalOpeningOriginalV1);

impl NetworkBrokerSessionCapturedJournalOpenV4 {
    /// Creates an inert fixed Session original without acquiring a descriptor.
    #[must_use]
    pub const fn new() -> Self {
        Self(NetworkCapturedJournalOpeningOriginalV1::session())
    }

    /// Prices the actual fixed capture before its genuine loan admits entry.
    ///
    /// # Errors
    /// Preserves checked geometry and the original native supplier refusal.
    pub fn fixed_preparation_demand() -> Result<ResourceVector, Cause> {
        NetworkCapturedJournalOpeningOriginalV1::fixed_demand(Recipe::Session)
    }

    /// Captures the same fixed Session names after actual receiving admission.
    pub fn prepare_once(&mut self, limits: JournalLimits, allow_create: bool) {
        self.0.prepare_once(limits, allow_create);
    }

    /// Borrows only the actual captured extent, before parser entry.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&CanonicalReplayExtentDataV1> {
        self.0.captured_extent()
    }

    /// Lends the same actual cursor and sampled file identity to Domain replay.
    ///
    /// # Errors
    /// Retains any original name, metadata, parser or ordering refusal.
    pub fn begin_replay_once(
        &mut self,
    ) -> Result<
        (
            aos_sandbox_journal::protected_storage::FileIdentity,
            CanonicalIndexedReplayV1<'_, '_>,
        ),
        Cause,
    > {
        self.0.begin_replay_once()
    }

    /// Finishes the same native tail after successful full Session semantics.
    ///
    /// # Errors
    /// Preserves native tail or ordering failures in this actual capture.
    pub fn finish_tail_once(&mut self) -> Result<(), Cause> {
        self.0.finish_tail_once()
    }

    /// Attempts the already-owed native after even after a semantic refusal.
    pub fn observe_after_owed_once(&mut self) {
        self.0.observe_after_owed_once();
    }

    /// Completes the actual Session native transfer before caller allocations.
    ///
    /// The completed bundle stays in the common owner until final transfer.
    #[must_use]
    pub fn prepare_held_transfer_once_v1(&mut self) -> Option<()> {
        self.0.prepare_held_transfer_once_v1()
    }

    /// Transfers the prepared Session bundle with a distinct late identity.
    ///
    /// The pre-native capture remains original to this opener. The actual
    /// caller separately prepays the supplied late payload and enforces its
    /// full Session semantics; this method creates no loan or role authority.
    #[must_use]
    pub fn take_prepared_held_with_independent_late_payload_once_v1<P, I>(
        &mut self,
        selection: P,
        payload: I,
    ) -> Option<(CanonicalOrdinaryHeldJournalV1<P, I>, RecoveryReport)> {
        self.0
            .take_prepared_held_with_independent_late_payload_once_v1(selection, payload)
    }

    /// Borrows the actual Session capture's intrinsic comparison identity.
    #[must_use]
    pub fn capture_identity_data_v1(&self) -> Option<CanonicalJournalInstanceDataV1> {
        self.0.capture_identity_data_v1()
    }

    /// Compares the actual capture without constructing a Journal or loan.
    #[must_use]
    pub fn same_capture_data_v1(&self, identity: &CanonicalJournalInstanceDataV1) -> bool {
        self.0.same_capture_data_v1(identity)
    }

    /// Borrows the original retained native cause without granting readiness.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.0.failure()
    }
}
