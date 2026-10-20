//! Retains the fixed Mount opening and its same-writer native bookends.
//!
//! This is the actual Mount file owner, not a Domain Journal adapter. Its
//! private identity link clones the completed held owner's original Arc and
//! cannot associate another Journal from supplied identity or replay DATA.

use aos_sandbox_broker::canonical_journal::CanonicalWriterOpeningOriginalsV1;
use aos_sandbox_broker::writer_currentness::WriterCurrentnessOriginalsV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use super::*;

pub(super) const DIRECTORY: &str = "/var/lib/aos/sandbox-mount";
pub(super) const NAME: &str = "mount.journal";

/// Selects the existing native create/repair or existing-only behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountCapturedJournalOpenModeV1 {
    /// Requires existing names and rejects stale compaction and incomplete tails.
    ExistingOnly,
    /// Permits missing names, stale compaction cleanup and incomplete-tail repair.
    CreateAndRepair,
}

/// Retains the fixed Mount state file through replay and every owed native post.
#[must_use = "retain partial opening and independent native posts on failure"]
pub struct MountStateCapturedJournalOpenV4 {
    original: MountOpeningOriginalV1,
    limits: Option<JournalLimits>,
    before: Option<Result<(), JournalError>>,
    after: Option<Result<(), JournalError>>,
    final_currentness: Option<Result<(), JournalError>>,
    closed: Option<JournalError>,
    replay_entered: bool,
    taken: bool,
    owner_link: Option<Arc<JournalAuthorityInstance>>,
    before_originals: WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    after_originals: WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    final_originals: [MountJournalCurrentnessOriginalsV1; 2],
}

impl MountStateCapturedJournalOpenV4 {
    /// Constructs vacant native and semantic destinations without allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            original: MountOpeningOriginalV1::new(),
            limits: None,
            before: None,
            after: None,
            final_currentness: None,
            closed: None,
            replay_entered: false,
            taken: false,
            owner_link: None,
            before_originals: WriterCurrentnessOriginalsV1::new(),
            after_originals: WriterCurrentnessOriginalsV1::new(),
            final_originals: [
                MountJournalCurrentnessOriginalsV1::new(),
                MountJournalCurrentnessOriginalsV1::new(),
            ],
        }
    }

    /// Prices this actual fixed native constructor before preparation.
    ///
    /// Replay/model growth is separately derived from the captured file extent.
    /// No demand value pays a receiver or establishes native role authority.
    #[must_use]
    pub fn fixed_preparation_demand() -> Result<ResourceVector, aos_sandbox_core::AccountingError> {
        Self::checked_fixed_preparation_demand().ok_or(
            aos_sandbox_core::AccountingError::ArithmeticOverflow {
                dimension: D::MemoryBytes,
            },
        )
    }

    fn checked_fixed_preparation_demand() -> Option<ResourceVector> {
        let path = Path::new(DIRECTORY);
        let native =
            CanonicalWriterOpeningOriginalsV1::additional_fixed_receiving_demand_v1(path, NAME)
                .ok()?;
        let original =
            CanonicalOrdinaryOpeningOriginalsV1::<()>::receiving_payload_construction_bytes_v1::<
                MountSelection,
                JournalAuthorityInstance,
            >()?;
        let instance = aos_sandbox_broker::canonical_journal::CanonicalJournalInstanceDataV1::<
            JournalAuthorityInstance,
        >::payload_allocation_receiving_bytes_v1()?;
        let upper = std::mem::size_of::<Self>()
            .checked_sub(std::mem::size_of::<CanonicalOrdinaryOpeningOriginalsV1<()>>())?
            .checked_mul(2)?;
        // The original post is a separate metadata return/comparison lane;
        // its real construction temporaries are not inferred from other sinks.
        let prefix_post = CapturedReplayPrefixPostV1::<JournalError>::receiving_memory_bytes_v1()?;
        let bytes = u64::try_from(
            original
                .checked_add(upper)?
                .checked_add(instance)?
                .checked_add(prefix_post)?,
        )
        .ok()?;
        let before =
            WriterCurrentnessOriginalsV1::<NativeJournalDataErrorV1>::fixed_demand_v1(path, NAME)
                .ok()?;
        let final_one = MountJournalCurrentnessOriginalsV1::fixed_demand_v1(path, NAME).ok()?;
        let semantic =
            ColdReplayOriginalV1::<CanonicalIndexedReplayErrorV1>::fixed_demand_v1().ok()?;
        let capture = CapturedAppendDataOwnerV1::<JournalError>::construction_demand_v1()?;
        native
            .checked_add(before)
            .ok()?
            .checked_add(before)
            .ok()?
            .checked_add(final_one)
            .ok()?
            .checked_add(final_one)
            .ok()?
            .checked_add(semantic)
            .ok()?
            .checked_add(capture)
            .ok()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .ok()
    }

    /// Prepares the compiled file once after the genuine caller's fixed debit.
    pub fn prepare_once(&mut self, limits: JournalLimits, mode: MountCapturedJournalOpenModeV1) {
        if self.limits.is_some() || self.closed.is_some() || self.taken {
            self.closed
                .get_or_insert(MechanicalError::ProtectedBoundary.into());
            return;
        }
        self.limits = Some(limits);
        self.original.prepare_once(
            Path::new(DIRECTORY),
            NAME,
            limits,
            0,
            mode == MountCapturedJournalOpenModeV1::CreateAndRepair,
            Disposition::Retained,
        );
    }

    /// Borrows the extent of this same held prefix before replay admission.
    #[must_use]
    pub fn captured_extent(&self) -> Option<&MountJournalReplayExtentV1> {
        if self.closed.is_some() || self.replay_entered || self.taken {
            return None;
        }
        self.original.extent.as_ref()?.as_ref().ok()
    }

    fn observe_names(
        original: &MountOpeningOriginalV1,
        limits: JournalLimits,
        sink: &mut WriterCurrentnessOriginalsV1<NativeJournalDataErrorV1>,
    ) -> Result<(), JournalError> {
        if let Some((journal, _)) = &original.opened {
            sink.begin(true)?;
            let result = (|| {
                let view = journal.native.read_view_v1();
                // The original post first observes names even on unhealthy
                // custody, then the exact path and final health comparison.
                view.observe_names_into(sink)?;
                if view.protected_name() != Some(NAME)
                    || view.protected_uid() != Some(0)
                    || view.limits() != limits
                {
                    return Err(NativeJournalDataErrorV1::ProtectedBoundary);
                }
                view.observe_directory_binding_into(Path::new(DIRECTORY), 0, sink)?;
                journal
                    .ensure_healthy()
                    .map_err(|_| NativeJournalDataErrorV1::Poisoned)
            })();
            return sink.finish(result).map_err(Into::into);
        }
        original
            .native
            .observe_names_retaining_v1(Path::new(DIRECTORY), NAME, 0, sink)
            .map_err(Into::into)
    }

    /// Replays the exact retained prefix after its separate receiving admission.
    ///
    /// Independent post-names run after any entered primary refusal. The caller
    /// cannot replace path, UID, limits, parser or original identity.
    pub fn replay_once(&mut self) {
        if self.replay_entered || self.closed.is_some() || self.taken {
            self.closed
                .get_or_insert(MechanicalError::ProtectedBoundary.into());
            return;
        }
        self.replay_entered = true;
        let Some(limits) = self.limits else {
            self.closed = Some(MechanicalError::ProtectedBoundary.into());
            return;
        };
        self.before = Some(Self::observe_names(
            &self.original,
            limits,
            &mut self.before_originals,
        ));
        self.before_originals.settle_positive_once_v1();
        if matches!(self.before, Some(Ok(()))) && self.original.failure().is_none() {
            self.original.replay_once();
        }
        self.after = Some(Self::observe_names(
            &self.original,
            limits,
            &mut self.after_originals,
        ));
        self.after_originals.settle_positive_once_v1();
        if self.replay_ready() {
            if let Some((journal, _)) = &self.original.opened {
                self.owner_link = Some(Arc::clone(&journal.authority_instance));
            }
        }
    }

    /// Reports complete mechanical replay and bookends without role authority.
    #[must_use]
    pub fn replay_ready(&self) -> bool {
        self.replay_entered
            && !self.taken
            && self.failure().is_none()
            && matches!(self.before, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
            && self.original.opened.is_some()
    }

    /// Transfers the same Journal after the final paid native checks.
    #[must_use]
    pub fn take_opened(&mut self) -> Option<(MountJournalV1, RecoveryReport)> {
        if !self.replay_ready() {
            return None;
        }
        if self.final_currentness.is_some() {
            self.closed = Some(MechanicalError::ProtectedBoundary.into());
            return None;
        }
        let limits = self.limits?;
        self.final_currentness = Some((|| {
            let (journal, _) = self
                .original
                .opened
                .as_ref()
                .ok_or(MechanicalError::ProtectedBoundary)?;
            journal.validate_held_owned_at_for_uid_retaining(
                DIRECTORY,
                NAME,
                0,
                &mut self.final_originals[0],
            )?;
            self.final_originals[0].settle_positive_once_v1();
            journal.require_protected_location_retaining(
                Path::new(DIRECTORY),
                NAME,
                0,
                limits,
                &mut self.final_originals[1],
            )
        })());
        if !matches!(self.final_currentness, Some(Ok(()))) {
            return None;
        }
        self.final_originals[1].settle_positive_once_v1();
        let (journal, _) = self.original.opened.as_mut()?;
        if journal.captured.is_some() {
            return None;
        }
        journal.captured = Some(CapturedAppendDataOwnerV1::new(DIRECTORY, NAME, 0));
        // Preserve the original capture construction before traversal retirement.
        // Refusal leaves that same complete opened Journal resident.
        self.original
            .native
            .retire_completed_traversal_once_v1()
            .ok()?;
        let opened = self.original.opened.take()?;
        self.taken = true;
        Some(opened)
    }

    /// Borrows the actual first refusal while all later debt remains resident.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .failure()
            .or_else(|| self.before_originals.failure())
            .or_else(|| self.before.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.after_originals.failure())
            .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.final_originals[0].failure())
            .or_else(|| self.final_originals[1].failure())
            .or_else(|| {
                self.final_currentness
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    /// Reports the positive transfer of this exact original native tuple.
    #[must_use]
    pub fn was_taken_positive_v1(&self) -> bool {
        self.taken
            && self.replay_entered
            && self.failure().is_none()
            && matches!(self.before, Some(Ok(())))
            && matches!(self.after, Some(Ok(())))
            && matches!(self.final_currentness, Some(Ok(())))
    }

    fn require_same_journal(&self, journal: &MountJournalV1) -> Result<(), JournalError> {
        if !self.taken
            || !self
                .owner_link
                .as_ref()
                .is_some_and(|original| Arc::ptr_eq(original, &journal.authority_instance))
        {
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        Ok(())
    }
}

impl Default for MountStateCapturedJournalOpenV4 {
    fn default() -> Self {
        Self::new()
    }
}

mod inventory_currentness;
pub use inventory_currentness::MountInventoryJournalCurrentnessOriginalV2;
