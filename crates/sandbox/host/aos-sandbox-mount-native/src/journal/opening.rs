//! Runs canonical acquisition, full semantic replay and tail on one Mount file.
//!
//! Retained openings keep every reached partial for their paid outer owner.
//! Ordinary openings use the same cursor and consume their actual errors only
//! at the original current/semantic/pending/index/native disposal frontiers.

use aos_sandbox_broker::canonical_journal::coordinator::indexed_replay::CanonicalIndexedReplayErrorV1;
use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryOpeningOriginalsV1, NativeJournalDataErrorV1,
};
use aos_sandbox_journal::protected_storage::CapturedReplayPrefixPostV1;
use aos_sandbox_journal::recovery::RecoveryTailMode;
use aos_sandbox_ledger_replay::cold::{ColdReplayOriginalV1, ColdReplayRemainderDataV1};

use super::*;

mod captured;
#[cfg(test)]
mod tests;
pub use captured::{
    MountCapturedJournalOpenModeV1, MountInventoryJournalCurrentnessOriginalV2,
    MountStateCapturedJournalOpenV4,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Disposition {
    Ordinary,
    Retained,
}

#[derive(Clone, Copy)]
enum ReplayFirst {
    Native,
    Semantic,
    PrefixPost,
    Materialization,
}

struct MountOpeningOriginalV1 {
    native: CanonicalOrdinaryOpeningOriginalsV1,
    semantic: ColdReplayOriginalV1,
    remainder: Option<ColdReplayRemainderDataV1>,
    extent: Option<Result<MountJournalReplayExtentV1, JournalError>>,
    replay: Option<Result<(), JournalError>>,
    prefix_post: Option<CapturedReplayPrefixPostV1<JournalError>>,
    prefix_result: Option<Result<(), JournalError>>,
    first: Option<ReplayFirst>,
    tail: Option<Result<(), NativeJournalDataErrorV1>>,
    opened: Option<(MountJournalV1, RecoveryReport)>,
    disposition: Option<Disposition>,
    allow_repair: bool,
    closed: Option<JournalError>,
}

impl MountOpeningOriginalV1 {
    fn new() -> Self {
        Self {
            native: CanonicalOrdinaryOpeningOriginalsV1::new(),
            semantic: ColdReplayOriginalV1::new(),
            remainder: None,
            extent: None,
            replay: None,
            tail: None,
            prefix_post: None,
            prefix_result: None,
            first: None,
            opened: None,
            disposition: None,
            allow_repair: false,
            closed: None,
        }
    }

    fn prepare_once(
        &mut self,
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
        disposition: Disposition,
    ) {
        if self.disposition.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        self.disposition = Some(disposition);
        self.allow_repair = allow_create;
        let prepared = match disposition {
            Disposition::Ordinary => {
                self.native
                    .prepare_ordinary_once_v1(directory, name, limits, uid, allow_create)
            }
            Disposition::Retained => {
                self.native
                    .prepare_retaining_once_v1(directory, name, limits, uid, allow_create)
            }
        };
        if prepared.is_err() {
            // The canonical owner retains the actual cause and partial native
            // graph. This projection cannot replace it or permit another open.
            self.closed = Some(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        self.extent = Some(
            self.native
                .prepared_extent_v1()
                .map_err(JournalError::from)
                .and_then(MountJournalReplayExtentV1::from_canonical_v1),
        );
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn prepare_unprotected_once(&mut self, path: &Path, limits: JournalLimits) {
        if self.disposition.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        self.disposition = Some(Disposition::Ordinary);
        self.allow_repair = true;
        if self
            .native
            .prepare_unprotected_ordinary_once_v1(path, limits)
            .is_err()
        {
            self.closed = Some(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        self.extent = Some(
            self.native
                .prepared_extent_v1()
                .map_err(JournalError::from)
                .and_then(MountJournalReplayExtentV1::from_canonical_v1),
        );
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn prepare_fixture_once(
        &mut self,
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
        disposition: Disposition,
    ) {
        if self.disposition.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        self.disposition = Some(disposition);
        self.allow_repair = allow_create;
        let prepared = match disposition {
            Disposition::Ordinary => self.native.prepare_fixture_ordinary_once_v1(
                directory, name, limits, uid, allow_create,
            ),
            Disposition::Retained => self.native.prepare_fixture_retaining_once_v1(
                directory, name, limits, uid, allow_create,
            ),
        };
        if prepared.is_err() {
            self.closed = Some(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        self.extent = Some(
            self.native
                .prepared_extent_v1()
                .map_err(JournalError::from)
                .and_then(MountJournalReplayExtentV1::from_canonical_v1),
        );
    }

    fn replay_once(&mut self) {
        if self.replay.is_some() || self.closed.is_some() || self.opened.is_some() {
            self.closed.get_or_insert(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        self.replay_body_once();
        // The retained prefix post is owed after attempted parser/semantics,
        // including their refusal. It cannot change the selected earlier cause.
        if self.disposition == Some(Disposition::Retained)
            && self.observe_prefix_post_once().is_err()
        {
            return;
        }
        if !matches!(self.replay, Some(Ok(()))) {
            return;
        }
        let tail = if self.allow_repair {
            RecoveryTailMode::RepairIncomplete
        } else {
            RecoveryTailMode::RejectIncomplete
        };
        self.tail = Some(self.native.finish_replayed_tail_once_v1(tail));
        if !matches!(self.tail, Some(Ok(()))) {
            self.first.get_or_insert(ReplayFirst::Native);
            return;
        }
        self.remainder = self.semantic.take_remainder_once();
        if self.remainder.is_none() {
            self.first.get_or_insert(ReplayFirst::Materialization);
            self.closed = Some(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        }
        let Some((native, report)) = self
            .native
            .take_held_with_late_payload_once_v1(MountSelection::Other, JournalAuthorityInstance)
        else {
            self.first.get_or_insert(
                if self.native.native_failure_v1().is_some()
                    || self.native.index_failure_v1().is_some()
                {
                    ReplayFirst::Native
                } else {
                    ReplayFirst::Materialization
                },
            );
            self.closed = Some(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ));
            return;
        };
        let Some(instance) = native.instance_data_v1() else {
            // The only transfer above always carries its privately constructed
            // late payload; this branch retains native rather than substituting
            // a fresh Arc or returning an owner without the original identity.
            std::process::abort();
        };
        let authority_instance = Arc::clone(instance.comparison_arc_v1());
        let Some(semantic) = self.remainder.take() else {
            std::process::abort();
        };
        self.opened = Some((
            MountJournalV1 {
                native,
                captured: None,
                interval: None,
                semantic,
                authority_instance,
                mount_git_coverage_denied: false,
            },
            report,
        ));
    }

    fn replay_body_once(&mut self) {
        self.replay = Some(self.replay_inner());
        if !matches!(self.replay, Some(Ok(()))) {
            self.first.get_or_insert(
                if self.native.native_failure_v1().is_some()
                    || self.native.index_failure_v1().is_some()
                {
                    ReplayFirst::Native
                } else {
                    ReplayFirst::Semantic
                },
            );
        }
    }

    fn observe_prefix_post_once(&mut self) -> Result<(), JournalError> {
        if self.prefix_result.is_some() || self.prefix_post.is_some() {
            self.closed
                .get_or_insert(MechanicalError::ProtectedBoundary.into());
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        self.prefix_result = Some(
            self.native
                .observe_captured_prefix_post_once_v1(&mut self.prefix_post),
        );
        if matches!(self.prefix_result, Some(Ok(())))
            && self
                .prefix_post
                .as_ref()
                .is_some_and(|post| post.failure().is_none())
        {
            Ok(())
        } else {
            self.first.get_or_insert(ReplayFirst::PrefixPost);
            Err(MechanicalError::StaleAuthoritySnapshot.into())
        }
    }

    fn replay_inner(&mut self) -> Result<(), JournalError> {
        let limits = self
            .extent
            .as_ref()
            .and_then(|extent| extent.as_ref().ok())
            .ok_or(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ))?
            .limits;
        let identity = self.native.prepare_parser_identity_once_v1()?;
        let mut cursor = match self.disposition {
            Some(Disposition::Retained) => self
                .native
                .begin_captured_replay_with_parser_metadata_once_v1()?,
            Some(Disposition::Ordinary) => self.native.begin_indexed_replay_once_v1()?,
            None => return Err(MechanicalError::ProtectedBoundary.into()),
        };
        // Retained native custody is independent from semantic family policy.
        // The old fixed Mount opener uses full ordinary(false) Cold semantics.
        self.semantic
            .observe_ordinary_indexed_once(&mut cursor, identity, limits)
            .map_err(|_| JournalError::from(MechanicalError::ProtectedBoundary))?;
        cursor
            .completed_prefix()
            .ok_or(MechanicalError::ProtectedBoundary)?;
        Ok(())
    }

    fn replay_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.replay.as_ref()?.as_ref().err().map(|cause| cause as _)
    }

    fn prefix_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.prefix_post
            .as_ref()
            .and_then(|post| post.failure())
            .or_else(|| {
                self.prefix_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(ReplayFirst::Native) => self
                .native
                .native_failure_v1()
                .or_else(|| self.native.index_failure_v1())
                .or_else(|| self.replay_failure())
                .or_else(|| self.tail.as_ref()?.as_ref().err().map(|cause| cause as _)),
            Some(ReplayFirst::Semantic) => {
                self.semantic.failure().or_else(|| self.replay_failure())
            }
            Some(ReplayFirst::PrefixPost) => self.prefix_failure(),
            Some(ReplayFirst::Materialization) => self.closed.as_ref().map(|cause| cause as _),
            None => None,
        };
        selected
            .or_else(|| self.native.native_failure_v1())
            .or_else(|| self.semantic.failure())
            .or_else(|| self.native.index_failure_v1())
            .or_else(|| self.extent.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.replay_failure())
            .or_else(|| self.prefix_failure())
            .or_else(|| self.tail.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    fn into_ordinary_error(mut self) -> JournalError {
        // Prospective semantic rows retire before the current native tuple.
        // Current native temporaries precede the older semantic scratch. The
        // canonical index and native prefix then keep their original ordering.
        self.semantic.dispose_ordinary_prospective_v1();
        let _ = self.native.dispose_ordinary_current_once_v1();
        let semantic = std::mem::replace(&mut self.semantic, ColdReplayOriginalV1::new());
        let (stopped, semantic_cause) = semantic.into_ordinary_errors();
        let _ = self.native.dispose_ordinary_pending_once_v1();
        let native =
            std::mem::replace(&mut self.native, CanonicalOrdinaryOpeningOriginalsV1::new());
        let (index, native_cause) = match native.into_ordinary_errors_v1() {
            Ok(causes) => causes,
            Err(_retained) => std::process::abort(),
        };
        match stopped {
            Some(CanonicalIndexedReplayErrorV1::Native(cause)) => {
                // The cursor's returned value may be its closed boundary marker;
                // its actual native original still owns the precise parser cause.
                return native_cause.unwrap_or(cause).into();
            }
            Some(CanonicalIndexedReplayErrorV1::Closed) => {
                if let Some(cause) = index {
                    return crate::journal::MechanicalError::from(cause).into();
                }
                if let Some(cause) = native_cause {
                    return cause.into();
                }
            }
            None => {
                if let Some(cause) = semantic_cause {
                    return cause.into();
                }
                if let Some(cause) = index {
                    return crate::journal::MechanicalError::from(cause).into();
                }
                if let Some(cause) = native_cause {
                    return cause.into();
                }
            }
        }
        self.extent
            .take()
            .and_then(Result::err)
            .or_else(|| self.replay.take().and_then(Result::err))
            .or(self.closed.take())
            .unwrap_or(JournalError::Mechanical(
                crate::journal::MechanicalError::ProtectedBoundary,
            ))
    }
}

impl MountJournalV1 {
    /// Opens an ordinary journal without claiming the fixed protected Mount role.
    ///
    /// The existing ordinary allocation and create/repair policy remains in
    /// force for moved fixtures. Fixed authority lenders reject this
    /// unprotected writer; production callers use the two fixed-file openers.
    ///
    /// # Errors
    /// Preserves the actual canonical acquisition, semantic or tail refusal.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn open(
        path: impl AsRef<Path>,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let mut original = MountOpeningOriginalV1::new();
        original.prepare_unprotected_once(path.as_ref(), limits);
        if original.failure().is_none() {
            original.replay_once();
        }
        if original.failure().is_none() {
            if let Some(pair) = original.opened.take() {
                return Ok(pair);
            }
        }
        Err(original.into_ordinary_error())
    }

    /// Opens an existing private test directory through canonical acquisition.
    ///
    /// This fixture omits production root ancestry only; it does not supply a
    /// native owner, map or protected replay result. Fixed live authority still
    /// checks its genuine production path and owner independently.
    ///
    /// # Errors
    /// Refuses unsafe final names, a foreign owner, lock conflict or bad replay.
    #[cfg(any(test, feature = "test-fixtures"))]
    #[doc(hidden)]
    pub fn open_protected_at_uid(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_fixture_at_uid(directory, name, limits, uid, true)
    }

    /// Opens an existing fixture journal without creation or tail repair.
    ///
    /// This fixture retains the canonical existing-name, owner, lock, stale
    /// compaction and complete-prefix checks. It supplies no fixed role grant.
    ///
    /// # Errors
    /// Refuses missing or unsafe names, stale compaction, incomplete tails,
    /// foreign ownership, lock conflicts or invalid semantic replay.
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn open_existing_protected_at_uid(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_fixture_at_uid(directory, name, limits, uid, false)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    fn open_fixture_at_uid(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
        uid: u32,
        allow_create: bool,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let mut original = MountOpeningOriginalV1::new();
        original.prepare_fixture_once(
            directory, name, limits, uid, allow_create, Disposition::Ordinary,
        );
        if original.failure().is_none() {
            original.replay_once();
        }
        if original.failure().is_none() {
            if let Some(pair) = original.opened.take() {
                return Ok(pair);
            }
        }
        Err(original.into_ordinary_error())
    }

    /// Opens the fixed root-owned Mount state file with its actual limits.
    ///
    /// The directory and basename are compiled into this native owner. Startup
    /// and Root lenders separately validate their original complete scope and
    /// limits; opening alone supplies neither a table nor a signing purpose.
    ///
    /// # Errors
    /// Preserves the actual acquisition, full semantic replay or tail refusal.
    pub fn open_fixed_protected_v1(
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        Self::open_protected_at(
            Path::new("/var/lib/aos/sandbox-mount"),
            "mount.journal",
            limits,
        )
    }

    pub(crate) fn open_protected_at(
        directory: &Path,
        name: &str,
        limits: JournalLimits,
    ) -> Result<(Self, RecoveryReport), JournalError> {
        let mut original = MountOpeningOriginalV1::new();
        original.prepare_once(directory, name, limits, 0, true, Disposition::Ordinary);
        if original.failure().is_none() {
            original.replay_once();
        }
        if original.failure().is_none() {
            if let Some(pair) = original.opened.take() {
                return Ok(pair);
            }
        }
        Err(original.into_ordinary_error())
    }
}
